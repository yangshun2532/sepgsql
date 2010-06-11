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



/*
 *
 *
 */
static Bitmapset *
fixup_whole_row_references(Oid relOid, int natts, Bitmapset *columns)
{
	Bitmapset	   *result;
	AttrNumber		attno;
	int				index;

	index = InvalidAttrNumber - FirstLowInvalidHeapAttributeNumber;

	if (!bms_is_member(index, columns))
		return columns;

	result = bms_copy(columns);
	result = bms_del_member(result, index);

	for (attno=1; attno <= natts; attno++)
	{
		Form_pg_attribute	attForm;
		HeapTuple			atttup;

		atttup = SearchSysCache2(ATTNUM,
								 ObjectIdGetDatum(relOid),
								 Int16GetDatum(attno));
		if (!HeapTupleIsValid(atttup))
			continue;

		attForm = (Form_pg_attribute) GETSTRUCT(atttup);
		if (!attForm->attisdropped)
		{
			index = attno - FirstLowInvalidHeapAttributeNumber;

			result = bms_add_member(result, index);
		}
		ReleaseSysCache(atttup);
	}
	return result;
}



/*
 *
 *
 */
static bool
sepgsql_relation_privileges(Oid relOid,
							Bitmapset *selected,
							Bitmapset *modified,
							uint32 required,
							bool abort)
{



	/*
	 * Hardwired Policy
	 * SE-PostgreSQL enforces:
	 * - clients cannot modify system catalogs
	 * - clients cannot reference/modify toast relations
	 */
	if (sepgsql_get_enforce())
	{
		if (IsSystemNamespace(get_rel_namespace(relOid)) &&
			(required & (SEPG_DB_TABLE__UPDATE |
						 SEPG_DB_TABLE__INSERT |
						 SEPG_DB_TABLE__DELETE)) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SELinux: unable to modify catalogs using DML")));

		if (get_rel_relkind(relOid) == RELKIND_TOASTVALUE)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SELinux: unable to access TOAST using DML")));
	}












}


/*
 * sepgsql_relation_privileges
 *
 *
 */
static bool
sepgsql_relation_privileges(List *rangeTabls, bool abort)
{
	ListCell   *l;

	foreach (l, rangeTabls)
	{
		RangeTblEntry  *rte = lfirst(l);
		uint32			required = 0;

		if (rte->rtekind != RTE_RELATION)
			continue;

		/* find out required permissions */
		if (rte->requiredPerms & ACL_SELECT)
			required |= SEPG_DB_TABLE__SELECT;
		if (rte->equiredPerms & ACL_INSERT)
			required |= SEPG_DB_TABLE__INSERT;
		if (rte->requiredPerms & ACL_UPDATE)
		{
			if (!bms_is_empty(rte->modifiedCols))
				required |= SEPG_DB_TABLE__UPDATE;
			else
				required |= SEPG_DB_TABLE__LOCK;
		}
		if (rte->required & ACL_DELETE)
			required |= SEPG_DB_TABLE__DELETE;

		if (required == 0)
			continue;

		if (!sepgsql_relation_privileges(rte->relid,
										 rte->selectedCols,
										 rte->modifiedCols,
										 required, abort))
			return false;
	}
	return true;
}

/*
 * sepgsql_register_hooks
 *
 * It sets up security hooks correctly on starting up time.
 */
void
sepgsql_register_hooks(void)
{
	
}
