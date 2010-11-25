/*
 * relation.c
 *
 * It provides security hooks corresponding to relation object
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * Copyright (c) 2007 - 2010, NEC Corporation
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "access/tupdesc.h"
#include "catalog/catalog.h"
#include "catalog/heap.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_inherits_fn.h"
#include "commands/seclabel.h"
#include "commands/tablecmds.h"
#include "executor/executor.h"
#include "nodes/bitmapset.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

#include "sepgsql.h"

/*
 * fixup_whole_row_references
 *
 * When user reference a whole of row, it is equivalent to reference to
 * all the user columns (not system columns). So, we need to fix up the
 * given bitmapset, if it contains a whole of the row reference.
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
 * fixup_inherited_columns
 *
 * When user is querying on a table with children, it implicitly accesses
 * child tables also. So, we also need to check security label of child
 * tables and columns, but here is no guarantee attribute numbers are
 * same between the parent ans children.
 * It returns a bitmapset which contains attribute number of the child
 * table based on the given bitmapset of the parent.
 */
static Bitmapset *
fixup_inherited_columns(Oid parentId, Oid childId, Bitmapset *columns)
{
	AttrNumber	attno;
	Bitmapset  *tmpset;
	Bitmapset  *result = NULL;
	char	   *attname;
	int			index;

	/*
	 * obviously, no need to do anything here
	 */
	if (parentId == childId)
		return columns;

	tmpset = bms_copy(columns);
	while ((index = bms_first_member(tmpset)) > 0)
	{
		attno = index + FirstLowInvalidHeapAttributeNumber;
		/*
		 * whole-row-reference shall be fixed-up later
		 */
		if (attno == InvalidAttrNumber)
		{
			result = bms_add_member(result, index);
			continue;
		}

		attname = get_attname(parentId, attno);
		if (!attname)
			elog(ERROR, "cache lookup failed for attribute %d of relation %u",
				 attno, parentId);
		attno = get_attnum(childId, attname);
		if (attno == InvalidAttrNumber)
			elog(ERROR, "cache lookup failed for attribute '%s' of relation %u",
				 attname, childId);

		index = attno - FirstLowInvalidHeapAttributeNumber;
		result = bms_add_member(result, index);

		pfree(attname);
	}
	bms_free(tmpset);

	return result;
}

/*
 * sepgsql_one_relation_privileges
 *
 * It actually checks required permissions on a certain relation
 * and its columns.
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
	if (sepgsql_avc_getenforce())
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
 * Check DML permissions
 */
bool
sepgsql_relation_privileges(List *rangeTabls, bool abort)
{
	ListCell   *lr;

	foreach (lr, rangeTabls)
	{
		RangeTblEntry  *rte = lfirst(lr);
		uint32			required = 0;
		List		   *tableIds;
		ListCell	   *li;

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
		 * If this RangeTblEntry is also supposed to reference inherited
		 * tables, we need to check security label of the child tables.
		 * So, we expand rte->relid into list of OIDs of inheritance
		 * hierarchy, then checker routine will be invoked for each
		 * relations.
		 */
		if (!rte->inh)
			tableIds = list_make1_oid(rte->relid);
		else
			tableIds = find_all_inheritors(rte->relid, NoLock, NULL);

		foreach (li, tableIds)
		{
			Oid			tableOid = lfirst_oid(li);
			Bitmapset  *selectedCols;
			Bitmapset  *modifiedCols;

			/*
			 * child table has different attribute numbers, so we need
			 * to fix up them.
			 */
			selectedCols = fixup_inherited_columns(rte->relid, tableOid,
												   rte->selectedCols);
			modifiedCols = fixup_inherited_columns(rte->relid, tableOid,
												   rte->modifiedCols);

			/*
			 * check permissions on individual tables
			 */
			if (!sepgsql_one_relation_privileges(tableOid,
												 selectedCols,
												 modifiedCols,
												 required, abort))
				return false;
		}
		list_free(tableIds);
	}
	return true;
}




/*****/
static List *
sepgsql_relation_create(const char *relName,
						Oid namespaceId,
						Oid tablespaceId,
						char relkind,
						TupleDesc tupdesc,
						bool createAs)
{
	SecLabelItem   *sl;
	char		   *tcontext = "system_u:object_r:sepgsql_table_t:s0";
	uint16			tclass;
	uint32			required;
	char			auname[NAMEDATALEN * 2 + 10];
	int				index;
	List		   *seclabels = NIL;

	if (relkind == RELKIND_RELATION)
		tclass = SEPG_CLASS_DB_TABLE;
	else if (relkind == RELKIND_SEQUENCE)
		tclass = SEPG_CLASS_DB_SEQUENCE;
	else if (relkind == RELKIND_VIEW)
		tclass = SEPG_CLASS_DB_TUPLE;
	else
		return NIL;

	required = SEPG_DB_TABLE__CREATE;
	if (createAs)
		required |= SEPG_DB_TABLE__INSERT;

	/* permission on the relation */
	sepgsql_compute_perms(sepgsql_get_client_label(),
						  tcontext,
						  tclass,
						  required,
						  relName,
						  true);

	sl = palloc0(sizeof(SecLabelItem));
	sl->object.classId = RelationRelationId;
	sl->object.objectId = InvalidOid;	/* to be assigned later */
	sl->object.objectSubId = 0;
	sl->tag = SEPGSQL_LABEL_TAG;
	sl->seclabel = tcontext;

	seclabels = list_make1(sl);

	if (relkind != RELKIND_RELATION)
		return seclabels;

	/* permission on the columns */
	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < tupdesc->natts;
		 index++)
	{
		Form_pg_attribute	attr;

		if (index == ObjectIdAttributeNumber && !tupdesc->tdhasoid)
			continue;

		if (index < 0)
			attr = SystemAttributeDefinition(index, tupdesc->tdhasoid);
		else
			attr = tupdesc->attrs[index];

		required = SEPG_DB_COLUMN__CREATE;
		if (createAs && index >= 0)
			required |= SEPG_DB_COLUMN__INSERT;

		snprintf(auname, sizeof(auname), "%s.%s", relName, NameStr(attr->attname));

		sepgsql_compute_perms(sepgsql_get_client_label(),
							  tcontext,
							  tclass,
							  required,
							  auname,
							  true);

		sl = palloc0(sizeof(SecLabelItem));
		sl->object.classId = RelationRelationId;
		sl->object.objectId = InvalidOid;		/* to be assigned later */
		sl->object.objectSubId = attr->attnum;
		sl->tag = SEPGSQL_LABEL_TAG;
		sl->seclabel = tcontext;
		seclabels = lappend(seclabels, sl);
	}
	return seclabels;
}

