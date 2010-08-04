/*
 * hooks.c
 *
 * It provides security hooks of SE-PostgreSQL
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * Copyright (c) 2007 - 2010, NEC Corporation
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/genam.h"
#include "access/sysattr.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_inherits.h"
#include "commands/seclabel.h"
#include "executor/executor.h"
#include "nodes/bitmapset.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/tqual.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

#include "sepgsql.h"

/*
 * fixup_whole_row_references
 *
 * It expands the given columns, if it contains whole of the row reference.
 */
static Bitmapset *
fixup_whole_row_references(Oid relOid, Bitmapset *columns)
{
	Bitmapset  *result;
	HeapTuple	tuple;
	AttrNumber	natts;
	AttrNumber	attno;
	int			index;

	/* if no whole of row references, do not anything */
	index = InvalidAttrNumber - FirstLowInvalidHeapAttributeNumber;
	if (!bms_is_member(index, columns))
		return columns;

	/* obtain number of attributes */
	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relOid);
	natts = ((Form_pg_class) GETSTRUCT(tuple))->relnatts;
	ReleaseSysCache(tuple);

	/* fix up the given columns */
	result = bms_copy(columns);
	result = bms_del_member(result, index);

	for (attno=1; attno <= natts; attno++)
	{
		tuple = SearchSysCache2(ATTNUM,
								ObjectIdGetDatum(relOid),
								Int16GetDatum(attno));
		if (!HeapTupleIsValid(tuple))
			continue;

		if (((Form_pg_attribute) GETSTRUCT(tuple))->attisdropped)
			continue;

		index = attno - FirstLowInvalidHeapAttributeNumber;

		result = bms_add_member(result, index);

		ReleaseSysCache(tuple);
	}
	return result;
}

/*
 * sepgsql_relation_privileges
 *
 * It actually checks required permissions on the relation/columns.
 */
static bool
sepgsql_one_relation_privileges(Oid relOid,
								Bitmapset *selected,
								Bitmapset *modified,
								uint32 required,
								bool abort)
{
	char		relkind = get_rel_relkind(relOid);
	char	   *tcontext;
	Bitmapset  *columns;
	AttrNumber	attno;

	/*
	 * Hardwired Policies:
	 * SE-PostgreSQL enforces
	 * - clients cannot modify system catalogs using DMLs
	 * - clients cannot reference/modify toast relations using DMLs
	 */
	if (sepgsql_get_enforce())
	{
		Oid		relnamespace = get_rel_namespace(relOid);

		if (IsSystemNamespace(relnamespace) &&
			(required & (SEPG_DB_TABLE__UPDATE |
						 SEPG_DB_TABLE__INSERT |
						 SEPG_DB_TABLE__DELETE)) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("SELinux: hardwired security policy violation")));

		if (relkind == RELKIND_TOASTVALUE)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("SELinux: hardwired security policy violation")));
	}

	/*
	 * Check permissions on the relation
	 */
	tcontext = sepgsql_get_label(RelationRelationId, relOid, 0);
	switch (relkind)
	{
		case RELKIND_RELATION:
			sepgsql_compute_perms(sepgsql_get_client_label(),
								  tcontext,
								  SEPG_CLASS_DB_TABLE,
								  required,
								  get_rel_name(relOid),
								  abort);
			break;

		case RELKIND_SEQUENCE:
			Assert((required & ~SEPG_DB_TABLE__SELECT) == 0);

			if (required & SEPG_DB_TABLE__SELECT)
				sepgsql_compute_perms(sepgsql_get_client_label(),
									  tcontext,
									  SEPG_CLASS_DB_SEQUENCE,
									  SEPG_DB_SEQUENCE__GET_VALUE,
									  get_rel_name(relOid),
									  abort);
			return true;

		default:
			/* nothing to be checked */
			return true;
	}

	/*
	 * Check permissions on the columns
	 */
	selected = fixup_whole_row_references(relOid, selected);
	modified = fixup_whole_row_references(relOid, modified);
	columns = bms_union(selected, modified);

	while ((attno = bms_first_member(columns)) >= 0)
	{
		uint32		column_perms = 0;
		char		audit_name[2*NAMEDATALEN+3];

		if (bms_is_member(attno, selected))
			column_perms |= SEPG_DB_COLUMN__SELECT;
		if (bms_is_member(attno, modified))
		{
			if (required & SEPG_DB_TABLE__UPDATE)
				column_perms |= SEPG_DB_COLUMN__UPDATE;
			if (required & SEPG_DB_TABLE__INSERT)
				column_perms |= SEPG_DB_COLUMN__INSERT;
		}
		if (column_perms == 0)
			continue;

		/* obtain column's permission */
		attno += FirstLowInvalidHeapAttributeNumber;
		tcontext = sepgsql_get_label(RelationRelationId, relOid, attno);
		snprintf(audit_name, sizeof(audit_name), "%s.%s",
				 get_rel_name(relOid), get_attname(relOid, attno));

		sepgsql_compute_perms(sepgsql_get_client_label(),
							  tcontext,
							  SEPG_CLASS_DB_COLUMN,
							  column_perms,
							  audit_name,
							  true);
	}
	return true;
}

/*
 * sepgsql_relation_privileges
 *
 * Entrypoint of the DML checker hook
 */
static bool
sepgsql_relation_privileges(List *rangeTabls, bool abort)
{
	ListCell   *l;

	foreach (l, rangeTabls)
	{
		RangeTblEntry  *rte = lfirst(l);
		uint32			required = 0;

		/*
		 * Only regular relations shall be checked
		 */
		if (rte->rtekind != RTE_RELATION)
			continue;

		/*
		 * Find out required permissions
		 */
		if (rte->requiredPerms & ACL_SELECT)
			required |= SEPG_DB_TABLE__SELECT;
		if (rte->requiredPerms & ACL_INSERT)
			required |= SEPG_DB_TABLE__INSERT;
		if (rte->requiredPerms & ACL_UPDATE)
		{
			if (!bms_is_empty(rte->modifiedCols))
				required |= SEPG_DB_TABLE__UPDATE;
			else
				required |= SEPG_DB_TABLE__LOCK;
		}
		if (rte->requiredPerms & ACL_DELETE)
			required |= SEPG_DB_TABLE__DELETE;

		/*
		 * Skip, if nothing to be checked
		 */
		if (required == 0)
			continue;

		/*
		 * Do actual permission checks
		 */
		if (!sepgsql_one_relation_privileges(rte->relid,
											 rte->selectedCols,
											 rte->modifiedCols,
											 required, abort))
			return false;
	}
	return true;
}

/*
 * sepgsql_relation_relabel
 *
 * It validates the given security label and privileges to relabel.
 */
static void
sepgsql_relation_relabel(const ObjectAddress *object,
						 const char *seclabel,
						 int expected_parents)
{
	Oid			relOid = object->objectId;
	AttrNumber	attnum = object->objectSubId;
	Relation	pg_inherit;
	SysScanDesc	scan;
	ScanKeyData	keys[1];
	HeapTuple	tuple;
	char	   *tcontext;
	uint16		tclass;

	/* security label validation */
	if (!seclabel || security_check_context((security_context_t)seclabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_NAME),
				 errmsg("invalid security label: \"%s\"", seclabel)));

	/*
	 * SELinux requires a series of inheritance hierarchy have same
	 * security label, so we forbid relabeling in the following cases.
	 * 1. when user specifies a table which is inherited from others.
	 *    (expected_parents == 0, but parent relations exist)
	 * 2. when user tries to relabel a table which has diamond-type
	 *    inheritance tree.
	 *    (# of actual parent > expexted_parents)
	 * 3. when user specifies a column which is inherited from others.
	 * 4. when user tries to relabel a column which is merged from
	 *    different inheritance hierarchy.
	 */
	if (attnum == InvalidAttrNumber)
	{
		pg_inherit = heap_open(InheritsRelationId, AccessShareLock);

		ScanKeyInit(&keys[0],
					Anum_pg_inherits_inhrelid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(relOid));

		scan = systable_beginscan(pg_inherit,
								  InheritsRelidSeqnoIndexId, true,
								  SnapshotNow, 1, keys);
		while (HeapTupleIsValid(tuple = systable_getnext(scan)))
			expected_parents--;

		systable_endscan(scan);

		heap_close(pg_inherit, AccessShareLock);

		if (expected_parents < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
					 errmsg("cannot relabel inherited relation \"%s\"",
							get_rel_name(relOid))));
	}
	else
	{
		int		inhcount;

		tuple = SearchSysCache2(ATTNUM,
								ObjectIdGetDatum(relOid),
								Int16GetDatum(attnum));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %d of relation %u",
				 attnum, relOid);

		inhcount = ((Form_pg_attribute) GETSTRUCT(tuple))->attinhcount;

		if (inhcount > expected_parents)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
					 errmsg("cannot relabel inherited column \"%s\"",
							get_attname(relOid, attnum))));

		ReleaseSysCache(tuple);
	}

	/*
	 * what is the appropriate object class?
	 */
	switch (get_rel_relkind(relOid))
	{
		case RELKIND_RELATION:
			tclass = SEPG_CLASS_DB_TABLE;
			break;

		case RELKIND_SEQUENCE:
			tclass = SEPG_CLASS_DB_SEQUENCE;
			break;

		default:
			tclass = SEPG_CLASS_DB_TUPLE;
			break;
	}

	/*
	 * check db_table/db_column:{setattr relabelfrom} permission
	 */
	tcontext = sepgsql_get_label(RelationRelationId, relOid, attnum);

	sepgsql_compute_perms(sepgsql_get_client_label(),
						  tcontext,
						  tclass,
						  SEPG_DB_TABLE__SETATTR |
						  SEPG_DB_TABLE__RELABELFROM,
						  get_rel_name(relOid),
						  true);
	/*
	 * check db_table/db_column:{relabelto} permission
	 */
	sepgsql_compute_perms(sepgsql_get_client_label(),
						  (security_context_t)seclabel,
						  tclass,
						  SEPG_DB_TABLE__RELABELTO,
						  get_rel_name(relOid),
						  true);
}

/*
 * sepgsql_object_relabel
 *
 * An entrypoint of SECURITY LABEL statement
 */
static void
sepgsql_object_relabel(const ObjectAddress *object,
					   const char *seclabel,
					   int expected_parents)
{
	switch (object->classId)
	{
		case RelationRelationId:
			sepgsql_relation_relabel(object, seclabel, expected_parents);
			break;

		default:
			elog(ERROR, "unsupported object type");
			break;
	}
}

/*
 * sepgsql_register_hooks
 *
 * It sets up security hooks correctly on starting up time.
 */
void
sepgsql_register_hooks(void)
{
	ExecutorCheckPerms_hook = sepgsql_relation_privileges;
	register_object_relabel_hook(SEPGSQL_LABEL_TAG,
								 sepgsql_object_relabel);
}
