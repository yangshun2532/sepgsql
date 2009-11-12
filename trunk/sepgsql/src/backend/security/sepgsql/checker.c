/*
 * src/backend/security/sepgsql/checker.c
 *    routines to check permission to execute DDL statements
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "catalog/catalog.h"
#include "catalog/pg_class.h"
#include "security/sepgsql.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"

/*
 * fixup_whole_row_reference
 *
 * PgSQL allows users to access whole of the row as follows:
 *
 *   postgres=# SELECT t, a, c FROM t;
 *       t    | a | c
 *   ---------+---+---
 *    (1,2,3) | 1 | 3
 *   (1 row)
 *
 * In the rte->selectedCols, it is marked as a reference to the column
 * with attnum=0. But it is equivalent to access all the regular columns
 * from the perspective of access controls.
 *
 * If necessary, this function modifies the given Bitmapset to set
 * corresponding bits to regular columns (expect for dropped ones).
 */
static Bitmapset *
fixup_whole_row_reference(Oid relOid, Bitmapset *columns)
{
	HeapTuple	tuple;
	Bitmapset  *result;
	AttrNumber	attno;
	AttrNumber	nattrs;

	attno = InvalidAttrNumber - FirstLowInvalidHeapAttributeNumber;
	if (!bms_is_member(attno, columns))
		return columns;		/* no need to fixup */

	/* get pg_class.relnatts */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relOid);

	nattrs = ((Form_pg_class) GETSTRUCT(tuple))->relnatts;

	ReleaseSysCache(tuple);

	/*
	 * expand whole row reference
	 */
	result = bms_copy(columns);
	result = bms_del_member(result, attno);

	for (attno = 1; attno < nattrs; attno++)
	{
		Form_pg_attribute	attForm;
		HeapTuple	tuple;
		int			index;

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(relOid),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			continue;	/* should not be happen */

		attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		if (!attForm->attisdropped)
		{
			index = attno - FirstLowInvalidHeapAttributeNumber;
			result = bms_add_member(result, index);
		}
		ReleaseSysCache(tuple);
	}

	return result;
}

/*
 * sepgsql_check_relation_perms
 *
 * It checks client's permissions to access contents of a certain table
 * and columns. If violated, it raised an error.
 * 
 * The caller has to provide OID of the table, a set of columns to be
 * selected/modified and required permissions correctly.
 * The set of columns are represented as Bitmapset in same manner with
 * RangeTblEntry structure.
 *
 * SE-PgSQL has a few hardwired rules to keep consistenct in access
 * controls. It prevents to modify system catalogs and to access toast
 * tables using regular DML statement in enforcing mode. User has to
 * manage database objects using DDL statement, and fetch large values
 * using regular detoast mechanism.
 */
static void
sepgsql_check_relation_perms(uint32 required,
							 Oid relOid, 
							 Bitmapset *selected,
							 Bitmapset *modified)
{
	Bitmapset	   *columns;
	Bitmapset	   *selected_ex;
	Bitmapset	   *modified_ex;
	AttrNumber		attno;

	/*
	 * SE-PgSQL hardwired policy
	 */
	if (sepgsql_get_enforce())
	{
		/*
		 * SE-PgSQL prevents to modify system catalogs by hand.
		 * It should be set up with regular DDL statements.
		 */
		if (IsSystemNamespace(get_rel_namespace(relOid)) &&
			(required & (SEPG_DB_TABLE__UPDATE |
						 SEPG_DB_TABLE__INSERT |
						 SEPG_DB_TABLE__DELETE)) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("SE-PgSQL prevents to modify \"%s\" by hand",
							get_rel_name(relOid))));
		/*
		 * SE-PgSQL prevents to access toast table by hand.
		 * It should be accesses using regular toast mechanism.
		 */
		if (get_rel_relkind(relOid) == RELKIND_TOASTVALUE)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("SE-PgSQL prevents to access \"%s\" by hand",
							get_rel_name(relOid))));
	}

	if (get_rel_relkind(relOid) != RELKIND_RELATION)
		return;

	/*
	 * Check table's permission
	 */
	sepgsql_relation_common(relOid, required, true);

	/*
	 * Check column's permission
	 */
	selected_ex = fixup_whole_row_reference(relOid, selected);
	modified_ex = fixup_whole_row_reference(relOid, modified);

	columns = bms_union(selected_ex, modified_ex);

	while ((attno = bms_first_member(columns)) >= 0)
	{
		uint32	col_perms = 0;

		if (bms_is_member(attno, selected_ex))
			col_perms |= SEPG_DB_COLUMN__SELECT;
		if (bms_is_member(attno, modified_ex))
		{
			if (required & SEPG_DB_TABLE__UPDATE)
				col_perms |= SEPG_DB_COLUMN__UPDATE;
			if (required & SEPG_DB_TABLE__INSERT)
				col_perms |= SEPG_DB_COLUMN__INSERT;
		}

		if (col_perms == 0)
			continue;

		attno += FirstLowInvalidHeapAttributeNumber;

		sepgsql_attribute_common(relOid, attno, col_perms, true);
	}

	if (selected_ex != selected)
		bms_free(selected_ex);

	if (modified_ex != modified)
		bms_free(modified_ex);

	bms_free(columns);
}

/*
 * sepgsql_check_rte_perms
 *
 * It is an entrypoint of sepgsql_check_relation_perms() when user accesses
 * a certain table using regular DML statements.
 * It can raise an error, if violated.
 * We assume this hook should be invoked just after ExecCheckRTEPerms()
 * which also checks permissions on RangeTblEntry
 *
 * rte : RangeTblEntry to be checked
 */
void
sepgsql_check_rte_perms(RangeTblEntry *rte)
{
	uint32	required = 0;

	if (!sepgsql_is_enabled())
		return;

	/*
	 * Only plain-relation RTEs need to be checked here.  Function RTEs
	 * should be checked by init_fcache when the function is prepared for
	 * execution.
	 * Join, subquery, and special RTEs need no checks.
	 */
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
		 * UPDATE statements needs a bit on rte->modifiedCols at least,
		 * so we use it as a watermark.
		 */
		if (!bms_is_empty(rte->modifiedCols))
			required |= SEPG_DB_TABLE__UPDATE;
		else
			required |= SEPG_DB_TABLE__LOCK;
	}
	if (rte->requiredPerms & ACL_DELETE)
		required |= SEPG_DB_TABLE__DELETE;

	/* no need to check anything? */
	if (required == 0)
		return;

	sepgsql_check_relation_perms(required,
								 rte->relid,
								 rte->selectedCols,
								 rte->modifiedCols);
}

/*
 * sepgsql_check_copy_perms
 *
 * It is an entrypoint of sepgsql_check_relation_perms() when user accesses
 * a certain table using COPY TO/FROM statement.
 * It can raise an error, if violated.
 *
 * rel : the target relation to be copied
 * attnumlist : a list of attribute number to be accessed.
 * is_from : True, if COPY FROM. Otherwise, COPY TO.
 */
void
sepgsql_check_copy_perms(Relation rel, List *attnumlist, bool is_from)
{
	Oid			relOid = RelationGetRelid(rel);
	Bitmapset  *columns = NULL;
	ListCell   *l;

	if (!sepgsql_is_enabled())
		return;

	foreach (l, attnumlist)
	{
		AttrNumber  attno = lfirst_int(l);

		attno -= FirstLowInvalidHeapAttributeNumber;
		columns = bms_add_member(columns, attno);
	}

	if (is_from)
		sepgsql_check_relation_perms(SEPG_DB_TABLE__INSERT,
									 relOid, NULL, columns);
	else
		sepgsql_check_relation_perms(SEPG_DB_TABLE__SELECT,
									 relOid, columns, NULL);
}
