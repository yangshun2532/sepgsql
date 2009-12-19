/*
 * src/backend/security/sepgsql/checker.c
 *    walks on given Query tree and applies checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "catalog/catalog.h"
#include "catalog/pg_security.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

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
	Bitmapset		   *columns;
	Bitmapset		   *selected_ex;
	Bitmapset		   *modified_ex;
	Form_pg_class		relForm;
	HeapTuple			reltup;
	sepgsql_sid_t		relsid;
	sepgsql_sid_t		attsid;
	AttrNumber			attno;
	uint16				tclass;

	/*
	 * Hardwired Policy:
	 * SE-PostgreSQL enforces that clients cannot modify system
	 * catalogs and access toast values using DML statements,
	 * except initial setting up phase.
	 */
	if (sepgsqlGetEnforce())
	{
		if (IsSystemNamespace(get_rel_namespace(relid)) &&
			(required & (SEPG_DB_TABLE__UPDATE |
						 SEPG_DB_TABLE__INSERT |
						 SEPG_DB_TABLE__DELETE)) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SE-PostgreSQL prevents to modidy \"%s\"",
							get_rel_name(relid))));
		if (get_rel_relkind(relid) == RELKIND_TOASTVALUE)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SE-PostgreSQL prevents to access \"%s\"",
							get_rel_name(relid))));
	}

	/*
	 * Check db_table:{...} or db_sequence permissions
	 */
	reltup = SearchSysCache(RELOID,
							ObjectIdGetDatum(relid),
							0, 0, 0);
	if (!HeapTupleIsValid(reltup))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	relForm = (Form_pg_class) GETSTRUCT(reltup);

	relsid = sepgsqlGetTupleSecid(RelationRelationId, reltup, &tclass);

	if (tclass != SEPG_CLASS_DB_TABLE)
	{
		/* check db_sequence:{xxx} permission */
		if (tclass == SEPG_CLASS_DB_SEQUENCE)
		{
			if (required & SEPG_DB_TABLE__SELECT)
			{
				sepgsqlClientHasPerms(relsid, tclass,
									  SEPG_DB_SEQUENCE__GET_VALUE,
									  NameStr(relForm->relname), true);
			}
		}
		ReleaseSysCache(reltup);
		return;
	}
	sepgsqlClientHasPerms(relsid, tclass, required,
						  NameStr(relForm->relname), true);

	/*
	 * Check db_column:{...} permissions
	 */
	selected_ex = fixupWholeRowReference(relid, relForm->relnatts, selected);
	modified_ex = fixupWholeRowReference(relid, relForm->relnatts, modified);
	columns = bms_union(selected_ex, modified_ex);

	while ((attno = bms_first_member(columns)) >= 0)
	{
		Form_pg_attribute	attForm;
		HeapTuple			atttup;
		uint32				attperms = 0;
		char				auname[2 * NAMEDATALEN + 3];

		if (bms_is_member(attno, selected_ex))
			attperms |= SEPG_DB_COLUMN__SELECT;
		if (bms_is_member(attno, modified_ex))
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
		atttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(relid),
								Int16GetDatum(attno),
								0, 0);
		if (!HeapTupleIsValid(atttup))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u",
				 attno, relid);

		attForm = (Form_pg_attribute) GETSTRUCT(atttup);
		if (attForm->attisdropped)
			elog(ERROR, "attribute %d of relation %u does not exist",
				 attno, relid);

		snprintf(auname, sizeof(auname), "%s.%s",
				 NameStr(relForm->relname),
				 NameStr(attForm->attname));
		attsid = sepgsqlGetTupleSecid(AttributeRelationId,
									  atttup, &tclass);
		sepgsqlClientHasPerms(attsid, tclass, attperms, auname, true);

		ReleaseSysCache(atttup);
	}

	ReleaseSysCache(reltup);

	if (selected_ex != selected)
		bms_free(selected_ex);

	if (modified_ex != modified)
		bms_free(modified_ex);

	bms_free(columns);
}

/*
 * sepgsqlCheckQueryPerms
 *   It checks permission for all the required tables/columns on
 *   generic user queries.
 */
void
sepgsqlCheckRTEPerms(RangeTblEntry *rte)
{
	access_vector_t		required = 0;

	if (!sepgsqlIsEnabled())
		return;

	if (rte->rtekind != RTE_RELATION)
		return;

	if (rte->requiredPerms & ACL_SELECT)
		required |= SEPG_DB_TABLE__SELECT;
	if (rte->requiredPerms & ACL_INSERT)
		required |= SEPG_DB_TABLE__INSERT;
	if (rte->requiredPerms & ACL_UPDATE)
	{
		/*
		 * ACL_SELECT_FOR_UPDATE is defined as an aliase of ACL_UPDATE,
		 * so we cannot determine whether the given relation is accessed
		 * with UPDATE statement or SELECT FOR SHARE/UPDATE immediately.
		 * UPDATE statements set a bit on rte->modifiedCols at least,
		 * so we use it as a watermark.
		 */
		if (!bms_is_empty(rte->modifiedCols))
			required |= SEPG_DB_TABLE__UPDATE;
		else
			required |= SEPG_DB_TABLE__LOCK;
	}
	if (rte->requiredPerms & ACL_DELETE)
		required |= SEPG_DB_TABLE__DELETE;

	if (required == 0)
		return;

	checkTabelColumnPerms(rte->relid,
						  rte->selectedCols,
						  rte->modifiedCols,
						  required);
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

	/* all checkes are done in sepgsqlCheckRTEPerms */
	if (!rel)
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

	checkTabelColumnPerms(RelationGetRelid(rel),
						  selected, modified,
						  is_from ? SEPG_DB_TABLE__INSERT
								  : SEPG_DB_TABLE__SELECT);
}

/*
 * sepgsqlExecScan
 *   makes a decision on the given tuple.
 */
bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, uint32 required, bool abort)
{
	sepgsql_sid_t	sid;
	uint16			tclass;

	if (!sepgsqlIsEnabled() ||
		!required ||
		RelationGetForm(rel)->relkind != RELKIND_RELATION ||
		RelationGetRelid(rel) == SecurityRelationId)
		return true;

	sid = sepgsqlGetTupleSecid(RelationGetRelid(rel), tuple, &tclass);
	/*
	 * Insert/Delete to an external attribute is equivalent to
	 * the set-attribute on the master
	 */
	if (sid.relid != RelationGetRelid(rel) &&
		(required & (SEPG_DB_TUPLE__INSERT | SEPG_DB_TUPLE__DELETE)))
	{
		required &= ~(SEPG_DB_TUPLE__INSERT | SEPG_DB_TUPLE__DELETE);
		required |= SEPG_DB_TUPLE__UPDATE;
	}

	return sepgsqlClientHasPerms(sid, tclass, required, NULL, abort);
}

uint32
sepgsqlSetupTuplePerms(RangeTblEntry *rte)
{
	AclMode		perms = 0;

	if (!sepgsqlIsEnabled())
		return 0;

	if (rte->rtekind != RTE_RELATION)
		return 0;

	if (rte->requiredPerms & ACL_SELECT)
		perms |= SEPG_DB_TUPLE__SELECT;
	if (rte->requiredPerms & ACL_UPDATE && !bms_is_empty(rte->modifiedCols))
		perms |= SEPG_DB_TUPLE__UPDATE;
	if (rte->requiredPerms & ACL_DELETE)
		perms |= SEPG_DB_TUPLE__DELETE;

	return perms;
}

/*
 * sepgsqlHeapTupleInsert
 *   It assigns a default security label, if no explicit security labels
 *   were given. In addition, it also checks db_tuple:{insert} for the
 *   tuple newly inserted, when it invoked from user's query.
 */
void
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	sepgsql_sid_t		sid;
	uint16				tclass;

	if (!sepgsqlIsEnabled())
		return;

	/*
	 * assigns a default security label, if not explicit one
	 */
	if (!OidIsValid(HeapTupleGetSecid(newtup)))
	{
		if (HeapTupleHasSecid(newtup))
			sepgsqlSetDefaultSecid(rel, newtup);
	}

	/*
	 * It does not check permission for the new tuples
	 * inserted by system internal stuff using
	 * simple_heap_insert();
	 */
	if (internal)
		return;

	sid = sepgsqlGetTupleSecid(RelationGetRelid(rel),
							   newtup, &tclass);
	sepgsqlClientHasPerms(sid, tclass, SEPG_DB_TUPLE__INSERT, NULL, true);
}

/*
 * sepgsqlHeapTupleUpdate
 *   It checks db_tuple:{relabelfrom relabelto} permission on
 *   the user queries. (Please note that it does not check
 *   system internal stuff via simple_heap_update)
 */
void
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup)
{
	Oid				secid;
	HeapTupleData	oldtup;
	Buffer			oldbuf;

	if (!sepgsqlIsEnabled())
		return;

	/*
	 * heap_update() preserves the original security label
	 * of the given tuple, if no explicit security label
	 * is assigned on the newer version.
	 * In this case, db_tuple:{update} is already checked
	 * at the sepgsqlExecScan() hook, so we don't need to
	 * check anything more.
	 */
	secid = HeapTupleGetSecid(newtup);
	if (!OidIsValid(secid))
		return;

	/*
	 * User gave an explicit security label
	 */
	ItemPointerCopy(otid, &oldtup.t_self);
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "failed to fetch old version of the tuple");

	if (secid != HeapTupleGetSecid(&oldtup))
	{
		sepgsql_sid_t	sid;
		uint16			tclass;

		/* db_tuple:{relabelfrom} for older security context */
		sid = sepgsqlGetTupleSecid(RelationGetRelid(rel),
								   &oldtup, &tclass);
		sepgsqlClientHasPerms(sid, tclass,
							  SEPG_DB_TUPLE__RELABELFROM,
							  NULL, true);

		/* db_tuple:{relabelto} for newer security label */
		sid = sepgsqlGetTupleSecid(RelationGetRelid(rel),
								   newtup, &tclass);
		sepgsqlClientHasPerms(sid, tclass,
							  SEPG_DB_TUPLE__RELABELTO,
							  NULL, true);
	}
	ReleaseBuffer(oldbuf);
}
