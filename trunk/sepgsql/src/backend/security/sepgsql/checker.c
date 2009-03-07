/*
 * src/backend/security/sepgsql/checker.c
 *    walks on given Query tree and applies checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_trigger.h"
#include "commands/trigger.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/lsyscache.h"
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

	/* db_table:{...} permissions */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	if (sepgsqlTupleObjectClass(RelationRelationId, tuple) != SECCLASS_DB_TABLE)
	{
		ReleaseSysCache(tuple);
		return;
	}

	audit_name = sepgsqlAuditName(RelationRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(RelationRelationId, tuple),
						  SECCLASS_DB_TABLE,
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
			attperms |= DB_COLUMN__SELECT;
		if (bms_is_member(attno, modified))
		{
			if (required & DB_TABLE__UPDATE)
				attperms |= DB_COLUMN__UPDATE;
			if (required & DB_TABLE__INSERT)
				attperms |= DB_COLUMN__INSERT;
		}
		if (attperms == 0)
			continue;

		/* remove the attribute number offset */
		attno += FirstLowInvalidHeapAttributeNumber;

		/*
		 * NOTE: HARDWIRED POLICY OF SE-POSTGRESQL
		 * - User cannot modify pg_rewrite.ev_action by hand, because
		 *   it stores a parsed Query tree which includes requiredPerms
		 *   and RangeTblEntry with selectedCols/modifiedCols.
		 *   The correctness of access controls depends on these data
		 *   are not manipulated unexpectedly.
		 *
		 * So, SE-PostgreSQL peremptorily prevent to modify them
		 */
		if ((attperms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT))
			&& relid == RewriteRelationId
			&& attno == Anum_pg_rewrite_ev_action)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SE-PostgreSQL peremptorily prevent to modify "
							"\"pg_rewrite.ev_action\" by hand")));

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
							  SECCLASS_DB_COLUMN,
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
			required = DB_TABLE__SELECT;
		if (rte->requiredPerms & ACL_INSERT)
			required = DB_TABLE__INSERT;
		if (rte->requiredPerms & ACL_UPDATE)
			required = DB_TABLE__UPDATE;
		if (rte->requiredPerms & ACL_DELETE)
			required = DB_TABLE__DELETE;

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
						  is_from ? DB_TABLE__INSERT : DB_TABLE__SELECT);
}

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
						  selected, modified, DB_TABLE__INSERT);
}

/*
 * HeapTuple INSERT/UPDATE/DELETE
 */
HeapTuple
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	Oid			relid = RelationGetRelid(rel);
	uint32		perms = SEPGSQL_PERMS_INSERT;

	if (!sepgsqlIsEnabled())
		return newtup;

	/*
	 * check db_procedure:{install}, if necessary
	 */
	sepgsqlCheckProcedureInstall(rel, newtup, NULL);

	if (HeapTupleHasSecLabel(relid, newtup) &&
		!HeapTupleGetSecLabel(relid, newtup))
	{
		Datum  *values;
		bool   *nulls;
		int		natts;

		Assert(!internal);

		natts = RelationGetNumberOfAttributes(rel);
		values = (Datum *) palloc(natts * sizeof(Datum));
		nulls = (bool *) palloc(natts * sizeof(bool));

		heap_deform_tuple(newtup, RelationGetDescr(rel), values, nulls);
		sepgsqlSetDefaultSecLabel(RelationGetRelid(rel),
								  values, nulls, PointerGetDatum(NULL));
		newtup = heap_form_tuple(RelationGetDescr(rel), values, nulls);
	}
	sepgsqlCheckObjectPerms(rel, newtup, NULL, perms, true);

	return newtup;
}

void
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid,
					   HeapTuple newtup, bool internal)
{
	Oid				relid = RelationGetRelid(rel);
	uint32			perms = SEPGSQL_PERMS_UPDATE;
	HeapTupleData	oldtup;
	Buffer			oldbuf;
	sepgsql_sid_t	newsid;
	sepgsql_sid_t	oldsid;

	if (!sepgsqlIsEnabled())
		return;

	ItemPointerCopy(otid, &oldtup.t_self);
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "SELinux: failed to fetch a tuple for sepgsqlHeapTupleDelete");

	/*
	 * check db_procedure:{install}, if necessary
	 */
	sepgsqlCheckProcedureInstall(rel, newtup, &oldtup);

	newsid = HeapTupleGetSecLabel(RelationGetRelid(rel), newtup);
	oldsid = HeapTupleGetSecLabel(RelationGetRelid(rel), &oldtup);

	if ((oldsid == NULL && newsid != NULL) ||
		(oldsid != NULL && newsid == NULL) ||
		(oldsid != NULL && newsid != NULL && strcmp(oldsid, newsid) != 0) ||
		(sepgsqlTupleObjectClass(relid, newtup)
			!= sepgsqlTupleObjectClass(relid, &oldtup)))
		perms |= SEPGSQL_PERMS_RELABELFROM;

	sepgsqlCheckObjectPerms(rel, &oldtup, newtup, perms, true);

	if (perms & SEPGSQL_PERMS_RELABELFROM)
	{
		perms = SEPGSQL_PERMS_RELABELTO;
		sepgsqlCheckObjectPerms(rel, newtup, NULL, perms, true);
	}
	ReleaseBuffer(oldbuf);
}

void
sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid, bool internal)
{
	access_vector_t	required = SEPGSQL_PERMS_DELETE;
	HeapTupleData	oldtup;
	Buffer			oldbuf;

	if (!sepgsqlIsEnabled())
		return;

	ItemPointerCopy(otid, &(oldtup.t_self));
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "SELinux: failed to fetch a tuple for sepgsqlHeapTupleDelete");

	sepgsqlCheckObjectPerms(rel, &oldtup, NULL, required, true);

	ReleaseBuffer(oldbuf);
}
