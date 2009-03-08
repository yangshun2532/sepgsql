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
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "commands/trigger.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

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
	if (((Form_pg_class) GETSTRUCT(tuple))->relkind != SEPG_CLASS_DB_TABLE)
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
	 * - User cannot modify pg_security.* by hand, because it holds
	 *   all the pairs of security identifier and label, so the
	 *   correctness of access controls depends on these data are
	 *   protected from unexpected manipulation.
	 * - User cannot modify pg_largeobject.* by hand, because we
	 *   assumes largeobjects are accessed via certain functions
	 *   such as lowrite(), so the correctness of access controls
	 *   depends on these data are protected from unexpected
	 *   manipulation.
	 *
	 * SE-PostgreSQL always prevent user's query tries to modify
	 * these system catalogs by hand. Please use approariate
	 * interfaces.
	 */
	mask = SEPG_DB_TABLE__UPDATE | SEPG_DB_TABLE__INSERT | SEPG_DB_TABLE__DELETE;
	if ((required & mask) != 0 && (relid == RewriteRelationId ||
								   relid == SecurityRelationId ||
								   relid == LargeObjectRelationId))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SE-PostgreSQL peremptorily prevent to modify "
						"\"%s\" system catalog by hand",
						NameStr(((Form_pg_class)GETSTRUCT(tuple))->relname))));

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
 * fixupRowTriggerPerms
 *   It adds db_tuple:{select}, if Before/After-Row-Trigger configured.
 */
static access_vector_t
fixupRowTriggerPerms(CmdType cmd, Relation rel, bool before)
{
	TriggerDesc	   *trigdesc = rel->trigdesc;
	Trigger		   *trigger;
	int				i;

	if (!trigdesc)
		return 0;

	for (i=0; i < trigdesc->numtriggers; i++)
	{
		trigger = &trigdesc->triggers[i];

		if (trigger->tgenabled &&
			TRIGGER_FOR_ROW(trigger->tgtype) &&
			((before && TRIGGER_FOR_BEFORE(trigger->tgtype)) ||
			 (!before && !TRIGGER_FOR_BEFORE(trigger->tgtype))) &&
			((cmd == CMD_UPDATE && TRIGGER_FOR_UPDATE(trigger->tgtype)) ||
			 (cmd == CMD_DELETE && TRIGGER_FOR_DELETE(trigger->tgtype))))
			return SEPG_DB_TUPLE__SELECT;
	}

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
 * Row-level decision making
 */
bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, AclMode required, bool abort)
{
	security_class_t	tclass;
	access_vector_t		permissions = 0;
	const char		   *audit_name;

	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	if (required & ACL_SELECT)
		permissions |= SEPG_DB_TUPLE__SELECT;
	if (required & ACL_UPDATE)
		permissions |= (SEPG_DB_TUPLE__UPDATE |
						fixupRowTriggerPerms(CMD_UPDATE, rel, true));
	if (required & ACL_DELETE)
		permissions |= (SEPG_DB_TUPLE__DELETE |
						fixupRowTriggerPerms(CMD_DELETE, rel, true));
	if (permissions == 0)
		return true;

	audit_name = sepgsqlAuditName(RelationGetRelid(rel), tuple);
	tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);
	return sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
								 tclass,
								 permissions,
								 audit_name, abort);
}

/*
 * checkTrustedAction
 */
static bool
checkTrustedAction(Relation rel, bool internal)
{
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	if (!internal)
		return false;

	if (RelationGetRelid(rel) == SecurityRelationId)
		return true;

	return false;
}

/*
 * HeapTuple INSERT/UPDATE/DELETE
 */
bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	security_class_t	tclass;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled() || checkTrustedAction(rel, internal))
		return true;

	/* check binary library installation */
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
	audit_name = sepgsqlAuditName(relid, newtup);
	return sepgsqlClientHasPerms(HeapTupleGetSecLabel(newtup),
								 tclass,
								 SEPG_DB_TUPLE__INSERT,
								 audit_name, internal);
}

bool
sepgsqlHeapTupleUpdate(Relation rel, HeapTuple oldtup,
					   HeapTuple newtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	access_vector_t		required = 0;
	security_class_t	newclass;
	security_class_t	oldclass;
	const char		   *audit_name;
	bool				rc;

	if (!sepgsqlIsEnabled() || checkTrustedAction(rel, internal))
		return true;

	/* preserve security label, if unchanged */
	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		sepgsql_sid_t	oldsid = HeapTupleGetSecLabel(oldtup);

		if (HeapTupleHasSecLabel(newtup))
			HeapTupleSetSecLabel(newtup, oldsid);
	}

	/* user's query is already checked in ExecScan */
	if (internal)
		required |= SEPG_DB_TUPLE__UPDATE;
	/* special case in column create/drop */
	if (relid == AttributeRelationId)
		required |= fixupColumnAvPerms(newtup, oldtup);
	/* special case for After-Row-Update trigger */
	if (!internal)
		required |= fixupRowTriggerPerms(CMD_UPDATE, rel, false);
	/* check binary library installation */
	if (relid == ProcedureRelationId)
		checkCLibraryInstallation(newtup, oldtup);
	/* check db_procedure:{install}, if necessary */
	sepgsqlCheckProcedureInstall(rel, newtup, oldtup);

	newclass = sepgsqlTupleObjectClass(relid, newtup);
	oldclass = sepgsqlTupleObjectClass(relid, oldtup);

	/* relabeled? */
	if (newclass != oldclass ||
		HeapTupleGetSecLabel(newtup) != HeapTupleGetSecLabel(oldtup))
		required |= SEPG_DB_TUPLE__RELABELFROM;

	if (required)
	{
		audit_name = sepgsqlAuditName(relid, oldtup);
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(oldtup),
								   oldclass,
								   required,
								   audit_name, internal);
		if (!rc)
			return false;
	}

	if (required & SEPG_DB_TUPLE__RELABELFROM)
	{
		audit_name = sepgsqlAuditName(relid, newtup);
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(newtup),
								   newclass,
								   SEPG_DB_TUPLE__RELABELTO,
								   audit_name, internal);
		if (!rc)
			return false;
	}

	return true;
}

bool
sepgsqlHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal)
{
	Oid					relid = RelationGetRelid(rel);
	access_vector_t		required = 0;
	security_class_t	tclass;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled() || checkTrustedAction(rel, internal))
		return true;

	/* user's query is already checked in ExecScan */
	if (internal)
		required |= SEPG_DB_TUPLE__DELETE;
	if (!internal)
		required |= fixupRowTriggerPerms(CMD_DELETE, rel, false);

	tclass = sepgsqlTupleObjectClass(relid, oldtup);
	audit_name = sepgsqlAuditName(relid, oldtup);
	return sepgsqlClientHasPerms(HeapTupleGetSecLabel(oldtup),
								 tclass,
								 SEPG_DB_TUPLE__DELETE,
								 audit_name, internal);
}
