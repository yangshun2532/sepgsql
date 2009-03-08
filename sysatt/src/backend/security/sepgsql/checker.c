/*
 * src/backend/security/sepgsql/checker.c
 *    walks on given Query tree and applies checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
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

		if (trigger->tgenabled &&
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

	/*
	 * NOTE: HARDWIRED POLICY IN SE-POSTGRESQL
	 * - User cannot modify pg_rewrite.* by hand, because it holds
	 *   a parsed Query tree which includes requiredPerms and
	 *   RangeTblEntry with selectedCols/modifiedCols.
	 *   The correctness of access controls depends on these data
	 *   are protected from unexpected manipulation..
	 * - User cannot modify pg_security.* by hand, because it holds
	 *   all the pairs of security identifier and label, so the
	 *   correctness of access controls depends on these data are
	 *   protected from unexpected manipulation.
	 *
	 * SE-PostgreSQL always prevent user's query tries to modify
	 * these system catalogs by hand. Please use approariate
	 * interfaces.
	 */
	mask = SEPG_DB_TABLE__UPDATE | SEPG_DB_TABLE__INSERT | SEPG_DB_TABLE__DELETE;
	if ((required & mask) != 0 && (relid == RewriteRelationId ||
								   relid == SecurityRelationId))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SE-PostgreSQL peremptorily prevent to modify "
						"\"%s\" system catalog by hand",
						NameStr(((Form_pg_class)GETSTRUCT(tuple))->relname))));

	if (sepgsqlTupleObjectClass(RelationRelationId, tuple) != SEPG_CLASS_DB_TABLE)
	{
		ReleaseSysCache(tuple);
		return;
	}

	audit_name = sepgsqlAuditName(RelationRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
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
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							  SEPG_CLASS_DB_COLUMN,
							  attperms,
							  audit_name, true);
		ReleaseSysCache(tuple);
	}
}

/*
 * sepgsqlCheckQueryPerms
 *   It checks permission for all the required tables/columns on
 *   generic DML queries.
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
 *   It checks permissions on the target table/columns on COPY statement.
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
 *   It checks db_table:{insert} permission for a table newly created
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
fixupColumnAvPerms(access_vector_t required, HeapTuple newtup, HeapTuple oldtup)
{
	Form_pg_attribute	oldatt = (Form_pg_attribute) GETSTRUCT(oldtup);
	Form_pg_attribute	newatt = (Form_pg_attribute) GETSTRUCT(newtup);
	Datum				olddat, newdat;
	bool				oldnull, newnull;
	int					length;

	if (oldatt->attisdropped == newatt->attisdropped)
		return required;

	if (!oldatt->attisdropped && newatt->attisdropped)
		required |= SEPG_DB_COLUMN__DROP;
	if (oldatt->attisdropped && !newatt->attisdropped)
		required |= SEPG_DB_COLUMN__CREATE;

	/*
	 * Compare oldtup/newtup.
	 * If they don't differ expect for attisdropped,
	 * drop SEPG_DB_COLUMN__SETATTR
	 */
	length = offsetof(FormData_pg_attribute, attisdropped);
	if (memcmp(oldatt, newatt, length) != 0)
		return required;
	if (oldatt->attinhcount != newatt->attinhcount)
		return required;

	newdat = SysCacheGetAttr(ATTNUM, newtup,
							 Anum_pg_attribute_attacl, &newnull);
	olddat = SysCacheGetAttr(ATTNUM, oldtup,
							 Anum_pg_attribute_attacl, &oldnull);
	if (newnull != oldnull)
		return required;
	if (newnull && DatumGetBool(OidFunctionCall2(F_ARRAY_NE, newdat, olddat)))
		return required;

	newdat = SysCacheGetAttr(ATTNUM, newtup,
							 Anum_pg_attribute_attselabel, &newnull);
	olddat = SysCacheGetAttr(ATTNUM, oldtup,
							 Anum_pg_attribute_attselabel, &oldnull);
	if (newnull != oldnull)
		return required;
	if (newnull && DatumGetBool(OidFunctionCall2(F_TEXTNE, newdat, olddat)))
		return required;

	return (required & ~SEPG_DB_COLUMN__SETATTR);
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

	if (HeapTupleIsValid(oldtup))
	{
		newpro = (Form_pg_proc) GETSTRUCT(newtup);
		oldpro = (Form_pg_proc) GETSTRUCT(oldtup);
		if (newpro->prolang != ClanguageId)
			return;

		newbin = SysCacheGetAttr(PROCOID, newtup,
								 Anum_pg_proc_probin, &isnull);
		if (!isnull)
		{
			oldbin = SysCacheGetAttr(PROCOID, oldtup,
									 Anum_pg_proc_probin, &isnull);
			if (isnull ||
				oldpro->prolang != newpro->prolang ||
				DatumGetBool(DirectFunctionCall2(byteane, oldbin, newbin)))
			{
				filename = TextDatumGetCString(newbin);
				sepgsqlCheckDatabaseInstallModule(filename);
			}
		}
	}
	else
	{
		newpro = (Form_pg_proc) GETSTRUCT(newtup);
		if (newpro->prolang == ClanguageId)
		{
			newbin = SysCacheGetAttr(PROCOID, newtup,
									 Anum_pg_proc_probin, &isnull);
			if (!isnull)
			{
				filename = TextDatumGetCString(newbin);
				sepgsqlCheckDatabaseInstallModule(filename);
			}
		}
	}
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

	if (!sepgsqlIsEnabled())
		return;

	/* check C-Function installation */
	if (relid == ProcedureRelationId)
		checkCLibraryInstallation(newtup, NULL);

	/* check db_procedure:{install}, if necessary */
	sepgsqlCheckProcedureInstall(rel, newtup, NULL);

	/* set default security context */
	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		if (HeapTupleHasSecLabel(newtup))
			sepgsqlSetDefaultSecLabel(rel, newtup);
	}

	tclass = sepgsqlTupleObjectClass(relid, newtup);
	if (tclass == SEPG_CLASS_DB_TUPLE)
		return;		/* Now, row-level stuff not provided */

	audit_name = sepgsqlAuditName(relid, newtup);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(newtup),
						  tclass,
						  SEPG_DB_TUPLE__INSERT,
						  audit_name, true);
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
	const char		   *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	ItemPointerCopy(otid, &oldtup.t_self);
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "SELinux: failed to fetch a tuple for sepgsqlHeapTupleDelete");

	/* preserve security label, if unchanged */
	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		sepgsql_sid_t	oldsid = HeapTupleGetSecLabel(&oldtup);

		if (HeapTupleHasSecLabel(newtup))
			HeapTupleSetSecLabel(newtup, oldsid);
	}

	/* special case in column create/drop */
	if (relid == AttributeRelationId)
		required = fixupColumnAvPerms(required, newtup, &oldtup);

	/* check C-Function installation */
	if (relid == ProcedureRelationId)
		checkCLibraryInstallation(newtup, &oldtup);

	/* check db_procedure:{install}, if necessary */
	sepgsqlCheckProcedureInstall(rel, newtup, &oldtup);

	newclass = sepgsqlTupleObjectClass(relid, newtup);
	oldclass = sepgsqlTupleObjectClass(relid, &oldtup);

	/* relabeled? */
	if (newclass != oldclass ||
		HeapTupleGetSecLabel(newtup) != HeapTupleGetSecLabel(&oldtup))
		required |= SEPG_DB_TUPLE__RELABELFROM;

	/* Now, row-level stuff not provided */
	if (oldclass != SEPG_CLASS_DB_TUPLE)
	{
		audit_name = sepgsqlAuditName(relid, newtup);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(&oldtup),
							  oldclass,
							  required,
							  audit_name, true);
	}

	if ((required & SEPG_DB_TUPLE__RELABELFROM) &&
		newclass != SEPG_CLASS_DB_TUPLE)
	{
		audit_name = sepgsqlAuditName(relid, &oldtup);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(newtup),
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

	if (!sepgsqlIsEnabled())
		return;

	ItemPointerCopy(otid, &(oldtup.t_self));
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "SELinux: failed to fetch a tuple for sepgsqlHeapTupleDelete");

	tclass = sepgsqlTupleObjectClass(relid, &oldtup);
	if (tclass != SEPG_CLASS_DB_TUPLE)
	{
		audit_name = sepgsqlAuditName(relid, &oldtup);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(&oldtup),
							  tclass,
							  SEPG_DB_TUPLE__DELETE,
							  audit_name, true);
	}
	ReleaseBuffer(oldbuf);
}
