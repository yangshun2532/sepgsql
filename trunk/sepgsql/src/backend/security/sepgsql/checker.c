/*
 * src/backend/security/sepgsql/checker.c
 *    walks on given Query tree and applies checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_trigger.h"
#include "commands/trigger.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * fixupSelectedColsByTrigger
 */
static Bitmapset *
fixupSelectedColsByTrigger(CmdType cmd, Relation rel, Bitmapset *selected)
{
	TriggerDesc	   *trigdesc = rel->trigdesc;
	Trigger		   *trigger;
	int				i;

	if (!trigdesc)
		return selected;

	for (i=0; i < trigdesc->numtriggers; i++)
	{
		/*
		 * NOTE: Row-UPDATE/DELETE trigger invocation implicitly
		 * delivers a whole-row-reference to user defined functions,
		 * so it is necessary to check "db_column:{select}" permission
		 * on whole of regular columns.
		 */
		trigger = &trigdesc->triggers[i];

		if (trigger->tgenabled != TRIGGER_DISABLED &&
			TRIGGER_FOR_ROW(trigger->tgtype) &&
			RI_FKey_trigger_type(trigger->tgfoid) == RI_TRIGGER_NONE &&
			((cmd == CMD_UPDATE && TRIGGER_FOR_UPDATE(trigger->tgtype)) ||
			 (cmd == CMD_DELETE && TRIGGER_FOR_DELETE(trigger->tgtype))))
		{
			selected = bms_add_member(selected, InvalidAttrNumber
								- FirstLowInvalidHeapAttributeNumber);
		}
	}

	return selected;
}

/*
 * fixupWholeRowReference
 */
static Bitmapset *
fixupWholeRowReference(Oid relid, int nattrs, Bitmapset *columns)
{
	Bitmapset  *result;
	AttrNumber	attno;

	attno = InvalidAttrNumber - FirstLowInvalidHeapAttributeNumber;

	if (!bms_is_member(attno, columns))
		return columns;		/* no need to fixup */

	result = bms_copy(columns);
	result = bms_del_member(result, attno);

	for (attno=1; attno <= nattrs; attno++)
	{
		Form_pg_attribute	attform;
		HeapTuple			atttup;

		atttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(relid),
								Int16GetDatum(attno),
								0, 0);
		if (!HeapTupleIsValid(atttup))
			continue;

		attform = (Form_pg_attribute) GETSTRUCT(atttup);
		if (!attform->attisdropped)
		{
			int		cindex = attno - FirstLowInvalidHeapAttributeNumber;
			result = bms_add_member(result, cindex);
		}
		ReleaseSysCache(atttup);
	}

	return result;
}

/*
 * checkTabelColumnPerms
 *   This functions applies table/column level permissions for
 *   all the appeared ones in user's query, and raises an error
 *   if violated.
 *   It also applies a few hardwired policy which prevent to
 *   modified some of system catalogs.
 */
static void
checkTabelColumnPerms(Oid relid, Bitmapset *selected, Bitmapset *modified,
					  access_vector_t required)
{
	HeapTuple		tuple;
	Bitmapset	   *columns;
	AttrNumber		attno;
	int				nattrs;
	const char	   *audit_name;
	access_vector_t	mask;

	/* db_table:{...} permissions */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	/* ignore, if the relation is not general relation */
	if (((Form_pg_class) GETSTRUCT(tuple))->relkind != RELKIND_RELATION)
	{
		ReleaseSysCache(tuple);
		return;
	}

	/*
	 * NOTE: HARDWIRED POLICY IN SE-POSTGRESQL
	 * - User cannot modify pg_rewrite.* by hand, because it holds
	 *   a parsed Query tree which includes requiredPerms and
	 *   RangeTblEntry with selectedCols/modifiedCols.
	 *   The correctness of access controls depends on these data
	 *   are protected from unexpected manipulation..
	 *
	 * SE-PostgreSQL always prevent user's query tries to modify
	 * these system catalogs by hand. Please use approariate
	 * interfaces.
	 */
	mask = SEPG_DB_TABLE__UPDATE | SEPG_DB_TABLE__INSERT | SEPG_DB_TABLE__DELETE;
	if ((required & mask) != 0 && (relid == RewriteRelationId))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SE-PostgreSQL peremptorily prevent to modify "
						"\"%s\" system catalog by hand",
						NameStr(((Form_pg_class)GETSTRUCT(tuple))->relname))));

	audit_name = sepgsqlAuditName(RelationRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(RelationRelationId, tuple),
						  SEPG_CLASS_DB_TABLE,
						  required,
						  audit_name, true);

	nattrs = ((Form_pg_class) GETSTRUCT(tuple))->relnatts;

	ReleaseSysCache(tuple);

	/* db_column:{...} permissions */
	selected = fixupWholeRowReference(relid, nattrs, selected);
	modified = fixupWholeRowReference(relid, nattrs, modified);
	columns = bms_union(selected, modified);
	while ((attno = bms_first_member(columns)) >= 0)
	{
		Form_pg_attribute	attForm;
		access_vector_t		attperms = 0;

		if (bms_is_member(attno, selected))
			attperms |= SEPG_DB_COLUMN__SELECT;
		if (bms_is_member(attno, modified))
		{
			if (required & SEPG_DB_TABLE__UPDATE)
				attperms |= SEPG_DB_COLUMN__UPDATE;
			if (required & SEPG_DB_TABLE__INSERT)
				attperms |= SEPG_DB_COLUMN__INSERT;
		}
		if (attperms == 0)
			continue;

		/* remove the attribute number offset */
		attno += FirstLowInvalidHeapAttributeNumber;

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(relid),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u", attno, relid);

		attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		if (attForm->attisdropped)
			elog(ERROR, "attribute %d of relation %u does not exist", attno, relid);

		audit_name = sepgsqlAuditName(AttributeRelationId, tuple);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(AttributeRelationId, tuple),
							  SEPG_CLASS_DB_COLUMN,
							  attperms,
							  audit_name, true);
		ReleaseSysCache(tuple);
	}
}

/*
 * sepgsqlCheckQueryPerms
 *   It checks permission for all the required tables/columns on
 *   generic user queries.
 */
void
sepgsqlCheckQueryPerms(CmdType cmd, EState *estate)
{
	Index		index = 0;
	ListCell   *l;

	if (!sepgsqlIsEnabled())
		return;

	foreach (l, estate->es_range_table)
	{
		RangeTblEntry	   *rte = (RangeTblEntry *) lfirst(l);
		access_vector_t		required = 0;
		Bitmapset		   *selected;
		Bitmapset		   *modified;

		index++;

		if (rte->rtekind != RTE_RELATION)
			continue;

		if (rte->requiredPerms & ACL_SELECT)
			required = SEPG_DB_TABLE__SELECT;
		if (rte->requiredPerms & ACL_INSERT)
			required = SEPG_DB_TABLE__INSERT;
		if (rte->requiredPerms & ACL_UPDATE)
			required = SEPG_DB_TABLE__UPDATE;
		if (rte->requiredPerms & ACL_DELETE)
			required = SEPG_DB_TABLE__DELETE;

		if (required == 0)
			continue;

		selected = rte->selectedCols;
		modified = rte->modifiedCols;

		if (estate->es_result_relations)
		{
			ResultRelInfo  *rinfo = estate->es_result_relations;
			int				i;

			for (i=0; i < estate->es_num_result_relations; i++)
			{
				if (index == rinfo[i].ri_RangeTableIndex)
				{
					Relation	rel = rinfo[i].ri_RelationDesc;

					selected = bms_copy(selected);
					selected = fixupSelectedColsByTrigger(cmd, rel, selected);
				}
			}
		}
		checkTabelColumnPerms(rte->relid, selected, modified, required);
	}
}

/*
 * sepgsqlCheckCopyTable
 *   It checks permissions on COPY TO/FROM.
 */
void
sepgsqlCheckCopyTable(Relation rel, List *attnumlist, bool is_from)
{
	Bitmapset	   *selected = NULL;
	Bitmapset	   *modified = NULL;
	ListCell	   *l;

	if (!sepgsqlIsEnabled())
		return;

	/* all checkes are done in sepgsqlCheckQueryPerms */
	if (!rel)
		return;

	/* no need to check on non-regular relation */
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return;

	foreach (l, attnumlist)
	{
		AttrNumber	attno = lfirst_int(l);

		attno -= FirstLowInvalidHeapAttributeNumber;
		if (is_from)
			modified = bms_add_member(modified, attno);
		else
			selected = bms_add_member(selected, attno);
	}

	if (is_from)
		selected = fixupSelectedColsByTrigger(CMD_INSERT, rel, selected);

	checkTabelColumnPerms(RelationGetRelid(rel), selected, modified,
						  is_from ? SEPG_DB_TABLE__INSERT : SEPG_DB_TABLE__SELECT);
}

/*
 * sepgsqlCheckSelectInto
 *   It checks db_table/db_column:{insert} on the table newly created
 */
void
sepgsqlCheckSelectInto(Relation rel)
{
	Bitmapset	   *selected = NULL;
	Bitmapset	   *modified = NULL;

	if (!sepgsqlIsEnabled())
		return;

	selected = fixupSelectedColsByTrigger(CMD_INSERT, rel, selected);
	modified = bms_add_member(modified,
					InvalidAttrNumber - FirstLowInvalidHeapAttributeNumber);

	checkTabelColumnPerms(RelationGetRelid(rel),
						  selected, modified, SEPG_DB_TABLE__INSERT);
}

/*
 * fixupColumnAvPerms
 *   To change pg_attribute.attisdropped means dropping a column,
 *   although this operation done by update, so it need to change
 *   required permmision in this special case.
 */
static access_vector_t
fixupColumnAvPerms(HeapTuple newtup, HeapTuple oldtup)
{
	Form_pg_attribute	oldatt = (Form_pg_attribute) GETSTRUCT(oldtup);
	Form_pg_attribute	newatt = (Form_pg_attribute) GETSTRUCT(newtup);

	if (!oldatt->attisdropped && newatt->attisdropped)
		return SEPG_DB_COLUMN__DROP;
	if (oldatt->attisdropped && !newatt->attisdropped)
		return SEPG_DB_COLUMN__CREATE;

	return 0;
}

/*
 * checkCLibraryInstallation
 *   It checks the correctness of C-library when user tries to
 *   create / replace C-functions.
 */
static void
checkCLibraryInstallation(HeapTuple newtup, HeapTuple oldtup)
{
	Form_pg_proc	oldpro, newpro;
	Datum			oldbin, newbin;
	char		   *filename;
	bool			isnull;

	newpro = (Form_pg_proc) GETSTRUCT(newtup);
	if (newpro->prolang != ClanguageId)
		return;

	newbin = SysCacheGetAttr(PROCOID, newtup,
							 Anum_pg_proc_probin, &isnull);
	if (isnull)
		return;

	if (HeapTupleIsValid(oldtup))
	{
		oldpro = (Form_pg_proc) GETSTRUCT(oldtup);
		oldbin = SysCacheGetAttr(PROCOID, oldtup,
								 Anum_pg_proc_probin, &isnull);
		if (!isnull &&
			oldpro->prolang == newpro->prolang &&
			DatumGetBool(DirectFunctionCall2(byteaeq, oldbin, newbin)))
			return;		/* no need to check, if unchanged */
	}
	filename = TextDatumGetCString(newbin);
	sepgsqlCheckDatabaseInstallModule(filename);
}

/*
 * checkTrustedAction
 *   It returns true, if we can ignore access controls for create/alter/drop
 *   on the given database objects.
 */
static bool
checkTrustedAction(Relation rel, bool internal)
{
	if (RelationGetRelid(rel) == DatabaseRelationId ||
		RelationGetRelid(rel) == RelationRelationId ||
		RelationGetRelid(rel) == AttributeRelationId ||
		RelationGetRelid(rel) == ProcedureRelationId)
		return false;

	return true;
}

/*
 * HeapTuple INSERT/UPDATE/DELETE
 */
void
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	security_class_t	tclass;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled() || checkTrustedAction(rel, internal))
		return;

	/* check binary library installation */
	if (relid == ProcedureRelationId)
		checkCLibraryInstallation(newtup, NULL);
	/* check db_procedure:{install}, if necessary */
	sepgsqlCheckProcedureInstall(rel, newtup, NULL);

	/*
	 * NOTE: we should assign a default security label here,
	 * but only a few relation has a capability to hold
	 * security label in this version.
	 * In addition, it should be assigned via enhanced
	 * DDL statement (SECURITY_LABEL = 'xxx') in the normal
	 * way. Using INSERT statement to add a new entry to
	 * system catalog is a quite corner case, so it simply
	 * raises an error.
	 */
	if (HeapTupleHasSecLabel(relid, newtup) &&
		!HeapTupleGetSecLabel(relid, newtup))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("No security label specified")));

	tclass = sepgsqlTupleObjectClass(relid, newtup);
	if (tclass != SEPG_CLASS_DB_TUPLE)
	{
		audit_name = sepgsqlAuditName(relid, newtup);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(relid, newtup),
							  tclass,
							  SEPG_DB_TUPLE__INSERT,
							  audit_name, true);
	}
}

void
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid,
					   HeapTuple newtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	access_vector_t		required = SEPG_DB_TUPLE__UPDATE;
	HeapTupleData		oldtup;
	Buffer				oldbuf;
	security_class_t	newclass;
	security_class_t	oldclass;
	sepgsql_sid_t		newsid;
	sepgsql_sid_t		oldsid;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled() || checkTrustedAction(rel, internal))
		return;

	ItemPointerCopy(otid, &oldtup.t_self);
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "SELinux: failed to fetch a tuple");

	/* special case in column create/drop */
	if (relid == AttributeRelationId)
		required |= fixupColumnAvPerms(newtup, &oldtup);
	/* check binary library installation */
	if (relid == ProcedureRelationId)
		checkCLibraryInstallation(newtup, &oldtup);
	/* check db_procedure:{install}, if necessary */
	sepgsqlCheckProcedureInstall(rel, newtup, &oldtup);

	newclass = sepgsqlTupleObjectClass(relid, newtup);
	oldclass = sepgsqlTupleObjectClass(relid, &oldtup);
	newsid = HeapTupleGetSecLabel(relid, newtup);
	oldsid = HeapTupleGetSecLabel(relid, &oldtup);

	if ((newclass != oldclass) ||
		(oldsid == NULL && newsid != NULL) ||
		(oldsid != NULL && newsid == NULL) ||
		(oldsid != NULL && newsid != NULL && strcmp(oldsid, newsid) != 0))
		required |= SEPG_DB_TUPLE__RELABELFROM;

	if (oldclass != SEPG_CLASS_DB_TUPLE)
	{
		audit_name = sepgsqlAuditName(relid, newtup);
		sepgsqlClientHasPerms(oldsid,
							  oldclass,
							  required,
							  audit_name, true);
	}

	if ((required & SEPG_DB_TUPLE__RELABELFROM) &&
		newclass != SEPG_CLASS_DB_TUPLE)
	{
		audit_name = sepgsqlAuditName(relid, &oldtup);
		sepgsqlClientHasPerms(newsid,
							  newclass,
							  SEPG_DB_TUPLE__RELABELTO,
							  audit_name, true);
	}
	ReleaseBuffer(oldbuf);
}

void
sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	security_class_t	tclass;
	HeapTupleData		oldtup;
	Buffer				oldbuf;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled() || checkTrustedAction(rel, internal))
		return;

	ItemPointerCopy(otid, &(oldtup.t_self));
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "SELinux: failed to fetch a tuple");

	tclass = sepgsqlTupleObjectClass(relid, &oldtup);
	if (tclass != SEPG_CLASS_DB_TUPLE)
	{
		audit_name = sepgsqlAuditName(relid, &oldtup);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(relid, &oldtup),
							  tclass,
							  SEPG_DB_TUPLE__DELETE,
							  audit_name, true);
	}
	ReleaseBuffer(oldbuf);
}
