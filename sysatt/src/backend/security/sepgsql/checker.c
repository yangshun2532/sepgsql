/*
 * src/backend/security/sepgsql/checker.c
 *    walks on given Query tree and applies checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "catalog/indexing.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "commands/trigger.h"
#include "executor/executor.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/prep.h"
#include "optimizer/tlist.h"
#include "parser/parsetree.h"
#include "security/sepgsql.h"
#include "utils/array.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * sepgsqlWalkerContext
 *
 * This structure holds a context during analyzing a given query.
 * selist is a list of SEvalItemXXX objects to enumerate appared
 * tables and columns. These are evaluated later, just before
 * executing query.
 * internal_use shows the current state whether the current
 * Node is chained with target list, or conditional clause.
 */
typedef struct sepgsqlWalkerContext
{
	struct sepgsqlWalkerContext *parent;
	Query  *query;		/* Query of current layer */
	List   *selist;		/* list of SelinuxEvalItem */
	bool	internal_use;
} sepgsqlWalkerContext;

#define seitem_index_to_attno(index)			\
	((index) + FirstLowInvalidHeapAttributeNumber + 1)
#define seitem_attno_to_index(attno)			\
	((attno) - FirstLowInvalidHeapAttributeNumber - 1)

/*
 * sepgsqlAddEvalTable
 * sepgsqlAddEvalTableRTE
 *
 * These function marks required permissions for a given relation
 * on selist. If is is not chained yet, it makes a new one.
 */
List *
sepgsqlAddEvalTable(List *selist, Oid relid, bool inh, uint32 perms)
{
	SelinuxEvalItem *seitem;
	Form_pg_class relForm;
	HeapTuple tuple;
	ListCell *l;

	foreach (l, selist)
	{
		seitem = (SelinuxEvalItem *) lfirst(l);
		Assert(IsA(seitem, SelinuxEvalItem));

		if (seitem->relid == relid && seitem->inh == inh)
		{
			seitem->relperms |= perms;
			return selist;
		}
	}

	/* not found, so create a new one */
	tuple = SearchSysCache(RELOID,
                           ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relid);
	relForm = (Form_pg_class) GETSTRUCT(tuple);

	seitem = makeNode(SelinuxEvalItem);
	seitem->relid = relid;
	seitem->inh = inh;
	seitem->relperms = perms;
	seitem->nattrs = seitem_attno_to_index(relForm->relnatts) + 1;
	seitem->attperms = palloc0(seitem->nattrs * sizeof(uint32));

	ReleaseSysCache(tuple);

	return lappend(selist, seitem);
}

static List *
sepgsqlAddEvalTableRTE(List *selist, RangeTblEntry *rte, uint32 perms)
{
	return sepgsqlAddEvalTable(selist, rte->relid, rte->inh, perms);
}

/*
 * sepgsqlAddEvalColumn
 * sepgsqlAddEvalColumnRTE
 *
 * These function marks required permissions for a given column
 * on selist. If is is not chained yet, it makes a new one.
 */
List *
sepgsqlAddEvalColumn(List *selist, Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	SelinuxEvalItem *seitem;
	Form_pg_class relForm;
	HeapTuple tuple;
	ListCell *l;
	int index = seitem_attno_to_index(attno);

	foreach (l, selist)
	{
		seitem = (SelinuxEvalItem *) lfirst(l);
		Assert(IsA(seitem, SelinuxEvalItem));

		if (seitem->relid == relid && seitem->inh == inh)
		{
			if (index >= seitem->nattrs)
			{
				uint32 *attperms, nattrs;

				/*
				 * NOTE: the following step has a possibility that
				 * index number overs seitem->nattrs
				 *
				 * 1. PREPARE p AS SELECT t FROM t;
				 * 2. ALTER TABLE t ADD COLUMN x int;
				 * 3. EXECUTE p;
				 *
				 * Because whole-row-reference is extracted to
				 * references to all the user columns, so table
				 * may have different number of columns between
				 * state.1 and state.3.
				 * In this case, we need to rebuild seitem->attperms
				 */

				tuple = SearchSysCache(RELOID,
									   ObjectIdGetDatum(relid),
									   0, 0, 0);
				if (!HeapTupleIsValid(tuple))
					elog(ERROR, "cache lookup failed for relation %u", relid);
				relForm = (Form_pg_class) GETSTRUCT(tuple);

				nattrs = seitem_attno_to_index(relForm->relnatts) + 1;
				attperms = palloc0(nattrs * sizeof(uint32));
				memcpy(attperms, seitem->attperms,
					   seitem->nattrs * sizeof(uint32));
				seitem->nattrs = nattrs;
				seitem->attperms = attperms;

				ReleaseSysCache(tuple);
			}

			if (index < 0 || index >= seitem->nattrs)
				elog(ERROR, "SELinux: invalid attribute number: %d at relation: %u",
					 attno, relid);

			seitem->attperms[index] |= perms;

			return selist;
		}
	}

	/* not found, so create a new one */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relid);
	relForm = (Form_pg_class) GETSTRUCT(tuple);

	seitem = makeNode(SelinuxEvalItem);
	seitem->relid = relid;
	seitem->inh = inh;
	seitem->relperms = 0;
	seitem->nattrs = seitem_attno_to_index(relForm->relnatts) + 1;
	seitem->attperms = palloc0(seitem->nattrs * sizeof(uint32));
	if (index < 0 || index >= seitem->nattrs)
		elog(ERROR, "SELinux: invalid attribute number: %d at relation: %u",
			 attno, relid);
	seitem->attperms[index] |= perms;

	ReleaseSysCache(tuple);

	return lappend(selist, seitem);
}

static List *
sepgsqlAddEvalColumnRTE(List *selist, RangeTblEntry *rte, AttrNumber attno, uint32 perms)
{
	uint32	t_perms = 0;

	t_perms |= (perms & DB_COLUMN__USE    ? DB_TABLE__USE    : 0);
	t_perms |= (perms & DB_COLUMN__SELECT ? DB_TABLE__SELECT : 0);
	t_perms |= (perms & DB_COLUMN__INSERT ? DB_TABLE__INSERT : 0);
	t_perms |= (perms & DB_COLUMN__UPDATE ? DB_TABLE__UPDATE : 0);
	selist = sepgsqlAddEvalTableRTE(selist, rte, t_perms);

	return sepgsqlAddEvalColumn(selist, rte->relid, rte->inh, attno, perms);
}

/*
 * addEvalForeignKeyConstraint
 *
 * This function cares special case handling for built-in FK constraints.
 * It adds minimum required permissions to refer columns.
 */
static List *
sepgsqlAddEvalForeignKey(List *selist, Form_pg_trigger trigger)
{
	HeapTuple		contup;
	AttrNumber		attkeys;
	Datum			conkeys;
	ArrayType	   *attrs;
	int16		   *attnum;
	int				index;
	bool			isnull;

	contup = SearchSysCache(CONSTROID,
							ObjectIdGetDatum(trigger->tgconstraint),
							0, 0, 0);
	if (!HeapTupleIsValid(contup))
		elog(ERROR, "SELinux: cache lookup failed for constraint %u",
			 trigger->tgconstrrelid);

	if (RI_FKey_trigger_type(trigger->tgfoid) == RI_TRIGGER_PK)
		attkeys = Anum_pg_constraint_confkey;
	else
		attkeys = Anum_pg_constraint_conkey;

	conkeys = SysCacheGetAttr(CONSTROID, contup, attkeys, &isnull);
	if (isnull)
		elog(ERROR, "SELinux: no columns constrainted");

	attrs = DatumGetArrayTypeP(conkeys);

	if (ARR_NDIM(attrs) != 1 ||
		ARR_HASNULL(attrs) ||
		ARR_ELEMTYPE(attrs) != INT2OID)
		elog(ERROR, "SELinux: unexpected constraint format");

	attnum = (int16 *) ARR_DATA_PTR(attrs);
	for (index = 0; index < ARR_DIMS(attrs)[0]; index++)
		selist = sepgsqlAddEvalColumn(selist, trigger->tgrelid, false,
									  attnum[index], DB_COLUMN__SELECT);
	ReleaseSysCache(contup);

	return selist;
}

/*
 * sepgsqlAddEvalTriggerFunc
 *
 * This function adds needed items into selist, to execute a trigger
 * function. At least, it requires permission set to execute a function
 * configured as a trigger, to select a table and whole of columns
 * because whole of a tuple is delivered to trigger functions.
 */
List *
sepgsqlAddEvalTriggerFunc(List *selist, Oid relid, int cmdType)
{
	Relation	rel;
	SysScanDesc scan;
	ScanKeyData skey;
	HeapTuple	tuple;

	rel = heap_open(TriggerRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				Anum_pg_trigger_tgrelid,
				BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));
	scan = systable_beginscan(rel, TriggerRelidNameIndexId,
							  true, SnapshotNow, 1, &skey);
	while (HeapTupleIsValid((tuple = systable_getnext(scan))))
	{
		Form_pg_trigger trigForm = (Form_pg_trigger) GETSTRUCT(tuple);

		/*
		 * Skip not-invoked triggers
		 */
		if (!trigForm->tgenabled)
			continue;
		if (cmdType == CMD_INSERT && !TRIGGER_FOR_INSERT(trigForm->tgtype))
			continue;
		if (cmdType == CMD_UPDATE && !TRIGGER_FOR_UPDATE(trigForm->tgtype))
			continue;
		if (cmdType == CMD_DELETE && !TRIGGER_FOR_DELETE(trigForm->tgtype))
			continue;

		/*
		 * per STATEMENT trigger cannot refer whole of a tuple
		 */
		if (!TRIGGER_FOR_ROW(trigForm->tgtype))
			continue;

		/*
		 * BEFORE-ROW-INSERT trigger cannot refer whole of a tuple
		 */
		if (TRIGGER_FOR_BEFORE(trigForm->tgtype) &&
			TRIGGER_FOR_INSERT(trigForm->tgtype))
			continue;

		switch (RI_FKey_trigger_type(trigForm->tgfoid))
		{
			/*
			 * NOTE: we can make sure build-in FK trigger functions
			 * are not necessary to refer whole of the columns.
			 * It only refers constrainted columns, so we can omit
			 * check rest of columns. This special care enables to
			 * set up FK constraint on a table which has partially
			 * visible columns.
			 * Elsewhere, we don't have any knowledge on user defined
			 * trigger functions, so it is necessary to check permission
			 * to refer whole of the columns.
			 */
		case RI_TRIGGER_PK:
		case RI_TRIGGER_FK:
			selist = sepgsqlAddEvalTable(selist, relid, false,
										 DB_TABLE__SELECT);
			selist = sepgsqlAddEvalForeignKey(selist, trigForm);
			break;

		default:	/* RI_TRIGGER_NONE */
			selist = sepgsqlAddEvalTable(selist, relid, false,
										 DB_TABLE__SELECT);
			selist = sepgsqlAddEvalColumn(selist, relid, false, 0,
										  DB_COLUMN__SELECT);
			break;
		}
	}
	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	return selist;
}

/*
 * sepgsqlExprWalker
 *
 * This function walks on the given expression tree to pick up
 * all the appeared tables and columns. Their identifiers are
 * chains on swc->selist to evaluate permissions on them later.
 *
 * walkVarHelper picks up an accessed column and its contained
 * table, and chains them on swc->selist.
 * When swc->internal_use is true, it means this reference
 * is checked as "use" permission because its contents are
 * consumed internally, and not to be returned to client directly.
 * Otherwise, "select" permission is applied.
 *
 * walkQueryHelper walks on Query structure.
 * The reason why we don't use query_tree_walker() is that
 * SE-PostgreSQL need to apply different permission between
 * targetList and havingQual, for example.
 */

static bool
sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc);

/*
 * wholeRefJoinWalker
 *
 * A corner case need to invoke this walker function.
 * When we use whole-row-reference on RTE_JOIN relation,
 * it should be extracted to whole-row-references on
 * sources relations.
 *
 * EXAMPLE:
 *   SELECT t4 FROM (t1 JOIN (t2 JOIN t3 USING (a)) USING (b)) AS t4;
 *
 * Because RangeTblEntry with RTE_JOIN does not have any identifiers
 * of its source relations, we have to scan Query->jointree again to
 * look up sources again. :(
 */
typedef struct
{
	Query *query;
	int rtindex;
	/*
	 * rtindex == 0 means we are now walking on the required JoinExpr
	 * or its leafs, so we need to pick up all the appeared relations
	 * under the JoinExpr in this case.
	 */
	List *selist;
	uint32 perms;
} wholeRefJoinWalkerContext;

static bool
wholeRefJoinWalker(Node *node, wholeRefJoinWalkerContext *jwc)
{
	if (!node)
		return false;

	if (IsA(node, JoinExpr))
	{
		JoinExpr *j = (JoinExpr *) node;

		if (j->rtindex == jwc->rtindex)
		{
			int rtindex_backup = jwc->rtindex;
			bool rc;

			jwc->rtindex = 0;
			rc = expression_tree_walker(node, wholeRefJoinWalker, jwc);
			jwc->rtindex = rtindex_backup;

			return rc;
		}
	}
	else if (IsA(node, RangeTblRef) && jwc->rtindex == 0)
	{
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex,
									  jwc->query->rtable);
		if (rte->rtekind == RTE_RELATION)
		{
			jwc->selist = sepgsqlAddEvalColumnRTE(jwc->selist, rte, 0, jwc->perms);
		}
	}
	return expression_tree_walker(node, wholeRefJoinWalker, jwc);
}

static void
walkVarHelper(Var *var, sepgsqlWalkerContext *swc)
{
	sepgsqlWalkerContext *cur = swc;
	Query		   *query;
	RangeTblEntry  *rte;
	int				lv;

	Assert(IsA(var, Var));

	for (lv = var->varlevelsup; lv > 0; lv--)
	{
		Assert(cur->parent != NULL);
		cur = cur->parent;
	}
	query = cur->query;

	rte = rt_fetch(var->varno, query->rtable);
	Assert(IsA(rte, RangeTblEntry));

	if (rte->rtekind == RTE_RELATION)
	{
		uint32 perms = swc->internal_use
			? DB_COLUMN__USE : DB_COLUMN__SELECT;

		swc->selist = sepgsqlAddEvalColumnRTE(swc->selist, rte,
											  var->varattno, perms);
	}
	else if (rte->rtekind == RTE_JOIN)
	{
		if (var->varattno == 0)
		{
			wholeRefJoinWalkerContext jwcData;

			jwcData.query = query;
			jwcData.rtindex = var->varno;
			jwcData.selist = swc->selist;
			jwcData.perms = swc->internal_use
				? DB_COLUMN__USE : DB_COLUMN__SELECT;

			wholeRefJoinWalker((Node *)query->jointree, &jwcData);
			swc->selist = jwcData.selist;
		}
		else
		{
			Node *node = list_nth(rte->joinaliasvars,
								  var->varattno - 1);
			sepgsqlExprWalker(node, swc);
		}
	}
}

static List *
walkQueryHelper(Query *query, sepgsqlWalkerContext *swc)
{
	sepgsqlWalkerContext swcData;
	RangeTblEntry *rte;

	memset(&swcData, 0, sizeof(swcData));
	swcData.parent = swc;
	swcData.selist = (!swc ? NIL : swc->selist);
	swcData.query = query;

	if (query->commandType != CMD_DELETE)
	{
		ListCell *l;

		foreach (l, query->targetList)
		{
			TargetEntry	   *tle = lfirst(l);

			Assert(IsA(tle, TargetEntry));

			if (tle->resjunk)
			{
				swcData.internal_use = true;
				sepgsqlExprWalker((Node *) tle->expr, &swcData);
				continue;
			}

			swcData.internal_use = false;
			sepgsqlExprWalker((Node *) tle->expr, &swcData);

			if (query->commandType != CMD_SELECT)
			{
				AttrNumber	attno = tle->resno;
				uint32		perms;

				if (query->commandType == CMD_UPDATE)
					perms = DB_COLUMN__UPDATE;
				else
					perms = DB_COLUMN__INSERT;

				rte = rt_fetch(query->resultRelation, query->rtable);
				Assert(IsA(rte, RangeTblEntry));

				swcData.selist
					= sepgsqlAddEvalColumnRTE(swcData.selist, rte, attno, perms);
			}
		}
	}
	else
	{
		/* no need to check column-level permission for DELETE */
		rte = rt_fetch(query->resultRelation, query->rtable);
		Assert(IsA(rte, RangeTblEntry));

		swcData.selist
			= sepgsqlAddEvalTableRTE(swcData.selist, rte, DB_TABLE__DELETE);
	}

	swcData.internal_use = false;
	sepgsqlExprWalker((Node *) query->returningList, &swcData);

	swcData.internal_use = true;
	sepgsqlExprWalker((Node *) query->jointree, &swcData);
	sepgsqlExprWalker((Node *) query->setOperations, &swcData);
	sepgsqlExprWalker((Node *) query->havingQual, &swcData);
	sepgsqlExprWalker((Node *) query->sortClause, &swcData);
	sepgsqlExprWalker((Node *) query->groupClause, &swcData);
	sepgsqlExprWalker((Node *) query->limitOffset, &swcData);
	sepgsqlExprWalker((Node *) query->limitCount, &swcData);
	sepgsqlExprWalker((Node *) query->cteList, &swcData);
	sepgsqlExprWalker((Node *) query->windowClause, &swcData);

	return swcData.selist;
}

static void
walkRangeTblRefHelper(RangeTblRef *rtr, sepgsqlWalkerContext *swc)
{
	Query *query = swc->query;
	RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

	Assert(IsA(rte, RangeTblEntry));

	switch (rte->rtekind)
	{
	case RTE_RELATION:
		if (rtr->rtindex != query->resultRelation)
			swc->selist = sepgsqlAddEvalTableRTE(swc->selist, rte,
												 DB_TABLE__SELECT);
		break;

	case RTE_SUBQUERY:
		swc->selist = walkQueryHelper(rte->subquery, swc);
		break;

	case RTE_FUNCTION:
		sepgsqlExprWalker(rte->funcexpr, swc);
		break;

	case RTE_VALUES:
		sepgsqlExprWalker((Node *) rte->values_lists, swc);
		break;

	default:
		/* do nothing */
		break;
	}
}

static void
walkSortGroupClauseHelper(SortGroupClause *sgc, sepgsqlWalkerContext *swc)
{
	Query *query = swc->query;
	TargetEntry *tle
		= get_sortgroupref_tle(sgc->tleSortGroupRef,
							   query->targetList);

	Assert(IsA(tle, TargetEntry));

	sepgsqlExprWalker((Node *) tle->expr, swc);
}

static bool
sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc)
{
	if (node == NULL)
		return false;
	else if (IsA(node, Var))
		walkVarHelper((Var *) node, swc);
	else if (IsA(node, RangeTblRef))
		walkRangeTblRefHelper((RangeTblRef *) node, swc);
	else if (IsA(node, Query))
	{
		swc->selist
			= walkQueryHelper((Query *) node, swc);
	}
	else if (IsA(node, SortGroupClause))
	{
		walkSortGroupClauseHelper((SortGroupClause *) node, swc);

		return false;
	}
	return expression_tree_walker(node, sepgsqlExprWalker, (void *) swc);
}

/*
 * sepgsqlPostQueryRewrite
 *
 * This function is invoked just after given queries are rewritten
 * via query-rewritter phase. It walks on given query trees to
 * picks up all appeared tables and columns, and to chains the list
 * of them on query->selinuxItems.
 * This list is used to evaluate permissions later, just before
 * the query execution.
 *
 * It do nothing for DDL queries, because these are processed in
 * sepgsqlProcessUtility() hook.
 */
void
sepgsqlPostQueryRewrite(List *queryList)
{
	ListCell   *l;

	if (!sepgsqlIsEnabled())
		return;

	foreach (l, queryList)
	{
		Query  *query = (Query *) lfirst(l);

		Assert(IsA(query, Query));

		if (query->commandType == CMD_SELECT ||
			query->commandType == CMD_UPDATE ||
			query->commandType == CMD_INSERT ||
			query->commandType == CMD_DELETE)
		{
			query->selinuxItems
				= walkQueryHelper(query, NULL);
		}
	}
}

/*
 * checkSelinuxEvalItem
 *   checks give SelinuxEvalItem object based on the security
 *   policy of SELinux.
 */
void
sepgsqlCheckSelinuxEvalItem(SelinuxEvalItem *seitem)
{
	Form_pg_class relForm;
	Form_pg_attribute attForm;
	HeapTuple tuple;
	AttrNumber attno;
	const char *audit_name;
	int index;

	Assert(IsA(seitem, SelinuxEvalItem));

	/*
	 * Permission checks on table
	 */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(seitem->relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation: %u",
			 seitem->relid);
	relForm = (Form_pg_class) GETSTRUCT(tuple);
	if (relForm->relkind != RELKIND_RELATION)
	{
		ReleaseSysCache(tuple);
		return;
	}
	audit_name = sepgsqlAuditName(RelationRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SECCLASS_DB_TABLE,
						  seitem->relperms,
						  audit_name, true);
	ReleaseSysCache(tuple);

	/*
	 * Expand whole-row-reference
	 */
	index = seitem_attno_to_index(InvalidAttrNumber);
	if (seitem->attperms[index] != 0)
	{
		uint32 perms = seitem->attperms[index];

		seitem->attperms[index] = 0;
		for (index++; index < seitem->nattrs; index++)
			seitem->attperms[index] |= perms;
	}

	/*
	 * Permission checks on columns
	 */
	for (index = 0; index < seitem->nattrs; index++)
	{
		if (seitem->attperms[index] == 0)
			continue;

		attno = seitem_index_to_attno(index);
		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(seitem->relid),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %u",
				 attno, seitem->relid);
		attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		/*
		 * NOTE: When user uses whole-row-reference on a table
		 * which has already dropped column, the column can have
		 * non-zero required permissions, but being ignorable.
		 */
		if (attForm->attisdropped)
		{
			ReleaseSysCache(tuple);
			continue;
		}

		audit_name = sepgsqlAuditName(AttributeRelationId, tuple);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							  SECCLASS_DB_COLUMN,
							  seitem->attperms[index],
							  audit_name, true);
		ReleaseSysCache(tuple);
	}
}

static List *
expandEvalItemInheritance(List *selist)
{
	List	   *result = NIL;
	List	   *inherits;
	ListCell   *l, *i;
	int index;

	foreach (l, selist)
	{
		SelinuxEvalItem *seitem = lfirst(l);

		Assert(IsA(seitem, SelinuxEvalItem));

		if (!seitem->inh)
		{
			result = lappend(result, seitem);
			continue;
		}
		
		inherits = find_all_inheritors(seitem->relid);
		foreach (i, inherits)
		{
			result = sepgsqlAddEvalTable(result, lfirst_oid(i), false,
										 seitem->relperms);
			for (index = 0; index < seitem->nattrs; index++)
			{
				Oid relid_inh = lfirst_oid(i);
				AttrNumber attno = seitem_index_to_attno(index);

				if (seitem->attperms[index] == 0)
					continue;

				/*
				 * No need to assign attribute number for itself
				 */
				if (seitem->relid == relid_inh)
				{
					result = sepgsqlAddEvalColumn(result, relid_inh, false,
												  attno, seitem->attperms[index]);
					continue;
				}

				if (attno == InvalidAttrNumber)
				{
					/* whole-row-reference */
					int nattrs = seitem_index_to_attno(seitem->nattrs);
					int pos;

					for (pos = 1; pos < nattrs; pos++)
					{
						char *attname = get_attname(seitem->relid, pos);

						if (!attname)
							elog(ERROR, "SELinux: cache lookup failed for "
								 "attribute %d of relation %u", pos, seitem->relid);

						attno = get_attnum(relid_inh, attname);
						if (attno == InvalidAttrNumber)
							continue;	/* already dropped? */

						result = sepgsqlAddEvalColumn(result, relid_inh, false,
													  attno, seitem->attperms[index]);
						pfree(attname);
					}
				}
				else
				{
					char   *attname = get_attname(seitem->relid, attno);

					if (!attname)
						elog(ERROR, "cache lookup failed for "
							 "attribute %d of relation %u", attno, seitem->relid);

					attno = get_attnum(relid_inh, attname);
					if (attno == InvalidAttrNumber)
						elog(ERROR, "cache lookup failed for "
							 "attribute %s of relation %u", attname, relid_inh);

					result = sepgsqlAddEvalColumn(result, relid_inh, false,
												  attno, seitem->attperms[index]);
					pfree(attname);
				}
			}
		}
	}
	return result;
}

/*
 * sepgsqlExecutorStart
 *
 * This function is invoked at the head of ExecutorStart, to evaluate
 * permissions to access appeared object within the given query.
 * Query->pgaceItem is a list of SelinuxEvalItem objects generated in
 * previous phase, and it is copied to PlannedStmt->pgaceItem in the
 * optimizer.
 * This functions expand given selist based on table inheritance,
 * adds additional permissions related to trigger functions, and
 * expands whole-row-references. Then, these items are evaluated
 * based on the security policy of SELinux.
 */
void
sepgsqlExecutorStart(QueryDesc *queryDesc, int eflags)
{
	PlannedStmt *pstmt = queryDesc->plannedstmt;
	RangeTblEntry *rte;
	List	   *selist;
	ListCell   *l;

	if (!sepgsqlIsEnabled())
		return;

	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;

	if (!pstmt->selinuxItems)
		return;

	Assert(IsA(pstmt->selinuxItems, List));
	selist = copyObject(pstmt->selinuxItems);

	/*
	 * expand table inheritances
	 */
	selist = expandEvalItemInheritance(selist);

	/*
	 * add checks for access via trigger function
	 */
	foreach(l, pstmt->resultRelations)
	{
		Index		rindex = lfirst_int(l);

		rte = rt_fetch(rindex, pstmt->rtable);
		Assert(IsA(rte, RangeTblEntry));

		selist = sepgsqlAddEvalTriggerFunc(selist, rte->relid,
										   pstmt->commandType);
	}

	/*
	 * Check SelinuxEvalItem
	 */
	foreach (l, selist)
		sepgsqlCheckSelinuxEvalItem((SelinuxEvalItem *) lfirst(l));
}
