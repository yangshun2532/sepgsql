/*
 * src/backend/security/sepgsql/proxy.c
 *    Proxying the given Query trees via SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/sysattr.h"
#include "catalog/heap.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "executor/executor.h"
#include "nodes/nodeFuncs.h"
#include "nodes/security.h"
#include "optimizer/clauses.h"
#include "optimizer/plancat.h"
#include "optimizer/prep.h"
#include "optimizer/tlist.h"
#include "parser/parsetree.h"
#include "security/pgace.h"
#include "storage/lock.h"
#include "utils/array.h"
#include "utils/fmgroids.h"
#include "utils/fmgrtab.h"
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
 * is_internal_use shows the current state whether the current
 * Node is chained with target list, or conditional clause.
 */
typedef struct sepgsqlWalkerContext
{
	struct sepgsqlWalkerContext *parent;
	Query  *query;	/* Query structure of current layer */
	List   *selist;	/* list of SEvalItemXXX */
	bool	is_internal_use;
} sepgsqlWalkerContext;

#define seitem_index_to_attno(index)			\
	((index) + FirstLowInvalidHeapAttributeNumber + 1)
#define seitem_attno_to_index(attno)			\
	((attno) - FirstLowInvalidHeapAttributeNumber - 1)


/*
 * addEvalRelation
 * addEvalRelationRTE
 *
 * These functions add a given relation into selist, if it is not
 * contained yet. In addition, addEvalRelationRTE also marks required 
 * permissions on rte->pgaceTuplePerms. It is delivered to Scan object
 * and we can use it on ExecScan hook to apply tuple-level access
 * controls.
 */
static List *
addEvalRelation(List *selist, Oid relid, bool inh, uint32 perms)
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
addEvalRelationRTE(List *selist, RangeTblEntry *rte, uint32 perms)
{
	rte->pgaceTuplePerms |= (perms & DB_TABLE__USE ? SEPGSQL_PERMS_USE : 0);
	rte->pgaceTuplePerms |=	(perms & DB_TABLE__SELECT ? SEPGSQL_PERMS_SELECT : 0);

	return addEvalRelation(selist, rte->relid, rte->inh, perms);
}

/*
 * addEvalAttribute
 * addEvalAttributeRTE
 *
 * These functions add a given attribute into selist, if it is not
 * contained yet. In addition, addEvalAttributeRTE also marks required 
 * permissions on rte->pgaceTuplePerms. It is delivered to Scan object
 * and we can use it on ExecScan hook to apply tuple-level access
 * controls.
 */
static List *
addEvalAttribute(List *selist, Oid relid, bool inh, AttrNumber attno, uint32 perms)
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
addEvalAttributeRTE(List *selist, RangeTblEntry *rte, AttrNumber attno, uint32 perms)
{
	uint32		tbl_perms = 0;

	tbl_perms |= (perms & DB_COLUMN__USE ? DB_TABLE__USE : 0);
	tbl_perms |= (perms & DB_COLUMN__SELECT ? DB_TABLE__SELECT : 0);
	tbl_perms |= (perms & DB_COLUMN__INSERT ? DB_TABLE__INSERT : 0);
	tbl_perms |= (perms & DB_COLUMN__UPDATE ? DB_TABLE__UPDATE : 0);
	selist = addEvalRelationRTE(selist, rte, tbl_perms);

	/*
	 * Special care for pg_largeobject.data
	 */
	if ((perms & DB_COLUMN__SELECT) != 0 &&
		rte->relid == LargeObjectRelationId &&
		attno == Anum_pg_largeobject_data)
		rte->pgaceTuplePerms |= SEPGSQL_PERMS_READ;

	return addEvalAttribute(selist, rte->relid, rte->inh, attno, perms);
}

/*
 * addEvalForeignKeyConstraint
 *
 * This function add special case handling for PK/FK constraints.
 * invoke trigger function requires to access rights for all attribute
 *
 */
static List *
addEvalForeignKeyConstraint(List *selist, Form_pg_trigger trigger)
{
	HeapTuple contup;
	Datum attdat;
	ArrayType *attrs;
	int index;
	int16 *attnum;
	bool isnull;

	contup = SearchSysCache(CONSTROID,
							ObjectIdGetDatum(trigger->tgconstraint),
							0, 0, 0);
	if (!HeapTupleIsValid(contup))
		elog(ERROR, "SELinux: cache lookup failed for constraint %u",
			 trigger->tgconstrrelid);

	if (trigger->tgfoid == F_RI_FKEY_CHECK_INS ||
		trigger->tgfoid == F_RI_FKEY_CHECK_UPD)
		attdat = SysCacheGetAttr(CONSTROID, contup,
								 Anum_pg_constraint_conkey, &isnull);
	else
		attdat = SysCacheGetAttr(CONSTROID, contup,
								 Anum_pg_constraint_confkey, &isnull);
	if (isnull)
		elog(ERROR, "null PK/FK for constraint %u",
			 trigger->tgconstrrelid);
	attrs = DatumGetArrayTypeP(attdat);

	if (ARR_NDIM(attrs) != 1 ||
		ARR_HASNULL(attrs) ||
		ARR_ELEMTYPE(attrs) != INT2OID)
		elog(ERROR, "SELinux: unexpected constraint %u", trigger->tgconstrrelid);

	attnum = (int16 *) ARR_DATA_PTR(attrs);
	for (index = 0; index < ARR_DIMS(attrs)[0]; index++)
		selist = addEvalAttribute(selist, trigger->tgrelid, false,
								  attnum[index], DB_COLUMN__SELECT);

	ReleaseSysCache(contup);

	return selist;
}

/*
 * addEvalTriggerFunction
 *
 * This function adds needed items into selist, to execute a trigger
 * function. At least, it requires permission set to execute a function
 * configured as a trigger, to select a table and whole of columns
 * because whole of a tuple is delivered to trigger functions.
 */
static List *
addEvalTriggerFunction(List *selist, Oid relid, int cmdType)
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
		Form_pg_class relForm;
		HeapTuple reltup;

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

		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(relid),
								0, 0, 0);
		relForm = (Form_pg_class) GETSTRUCT(reltup);

		selist = addEvalRelation(selist, relid, false, DB_TABLE__SELECT);

		if (RI_FKey_trigger_type(trigForm->tgfoid) != RI_TRIGGER_NONE)
			selist = addEvalForeignKeyConstraint(selist, trigForm);
		else
			selist = addEvalAttribute(selist, relid, false,
									  0, DB_COLUMN__SELECT);
		ReleaseSysCache(reltup);
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
 * When swc->is_internal_use is true, it means this reference
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

static void
sepgsqlExprWalkerFlags(Node *node, sepgsqlWalkerContext *swc,
					   bool is_internal_use);

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
			jwc->selist = addEvalAttributeRTE(jwc->selist, rte, 0, jwc->perms);
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
		uint32 perms = swc->is_internal_use
			? DB_COLUMN__USE : DB_COLUMN__SELECT;

		swc->selist = addEvalAttributeRTE(swc->selist, rte,
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
			jwcData.perms = swc->is_internal_use
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
			TargetEntry *tle = lfirst(l);
			bool is_security = false;

			Assert(IsA(tle, TargetEntry));

			if (tle->resjunk &&
				tle->resname &&
				strcmp(tle->resname, SecurityLabelAttributeName) == 0)
				is_security = true;

			if (tle->resjunk && !is_security)
			{
				sepgsqlExprWalkerFlags((Node *) tle->expr, &swcData, true);
				continue;
			}

			sepgsqlExprWalkerFlags((Node *) tle->expr, &swcData, false);

			if (query->commandType != CMD_SELECT)
			{
				AttrNumber attno = tle->resno;
				uint32 perms;

				if (is_security)
					attno = SecurityLabelAttributeNumber;

				if (query->commandType == CMD_UPDATE)
					perms = DB_COLUMN__UPDATE;
				else
					perms = DB_COLUMN__INSERT;

				rte = rt_fetch(query->resultRelation, query->rtable);
				Assert(IsA(rte, RangeTblEntry));

				swcData.selist
					= addEvalAttributeRTE(swcData.selist, rte, attno, perms);
			}
		}
	}
	else
	{
		/* no need to check column-level permission for DELETE */
		rte = rt_fetch(query->resultRelation, query->rtable);
		Assert(IsA(rte, RangeTblEntry));

		swcData.selist
			= addEvalRelationRTE(swcData.selist, rte, DB_TABLE__DELETE);
	}

	sepgsqlExprWalkerFlags((Node *) query->returningList, &swcData, false);
	sepgsqlExprWalkerFlags((Node *) query->jointree, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->setOperations, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->havingQual, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->sortClause, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->groupClause, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->limitOffset, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->limitCount, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->cteList, &swcData, true);
	sepgsqlExprWalkerFlags((Node *) query->windowClause, &swcData, true);

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
			swc->selist = addEvalRelationRTE(swc->selist, rte,
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

static void
sepgsqlExprWalkerFlags(Node *node, sepgsqlWalkerContext *swc,
					   bool is_internal_use)
{
	bool		saved_is_internal_use = swc->is_internal_use;

	swc->is_internal_use = is_internal_use;
	sepgsqlExprWalker(node, swc);
	swc->is_internal_use = saved_is_internal_use;
}

/*
 * sepgsqlPostQueryRewrite
 *
 * This function is invoked just after given queries are rewritten
 * via query-rewritter phase. It walks on given query trees to
 * picks up all appeared tables and columns, and to chains the list
 * of them on query->pgaceItem.
 * This list is used to evaluate permissions later, just before
 * the query execution.
 *
 * It do nothing for DDL queries, because these are processed in
 * sepgsqlProcessUtility() hook.
 */
List *
sepgsqlPostQueryRewrite(List *queryList)
{
	ListCell   *l;

	foreach (l, queryList)
	{
		Query  *query = (Query *) lfirst(l);

		Assert(IsA(query, Query));

		if (query->commandType == CMD_SELECT ||
			query->commandType == CMD_UPDATE ||
			query->commandType == CMD_INSERT ||
			query->commandType == CMD_DELETE)
		{
			query->pgaceItem
				= (Node *) walkQueryHelper(query, NULL);
		}
	}

	return queryList;
}

/*
 * checkSelinuxEvalItem
 *   checks give SelinuxEvalItem object based on the security
 *   policy of SELinux.
 */
static void
checkSelinuxEvalItem(SelinuxEvalItem *seitem)
{
	Form_pg_class relForm;
	Form_pg_attribute attForm;
	HeapTuple tuple;
	AttrNumber attno;
	const char *audit_name;
	int index;

	Assert(IsA(seitem, SelinuxEvalItem));

	/*
	 * Prevent to write pg_security by hand
	 */
	if (seitem->relid == SecurityRelationId &&
		(seitem->relperms & (DB_TABLE__UPDATE | DB_TABLE__INSERT | DB_TABLE__DELETE)))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not modify pg_security by hand")));

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

	audit_name = sepgsqlTupleName(RelationRelationId, tuple);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_TABLE,
							   seitem->relperms,
							   audit_name);
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

		audit_name = sepgsqlTupleName(AttributeRelationId, tuple);
		sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
								   SECCLASS_DB_COLUMN,
								   seitem->attperms[index],
								   audit_name);
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
			result = addEvalRelation(result, lfirst_oid(i), false,
									 seitem->relperms);
			for (index = 0; index < seitem->nattrs; index++)
			{
				Oid relid_inh = lfirst_oid(i);
				AttrNumber attno;

				if (seitem->attperms[index] == 0)
					continue;

				attno = seitem_index_to_attno(index);
				if (attno < 1 || seitem->relid == relid_inh)
				{
					/*
					 * If attribute is system-column or whole-row-reference,
					 * or inherit relation is itself, we don't need to fix up
					 * attribute number.
					 */
					result = addEvalAttribute(result, relid_inh, false,
											  attno, seitem->attperms[index]);
					continue;
				}
				else
				{
					char *attname = get_attname(seitem->relid, attno);

					if (!attname)
						elog(ERROR, "cache lookup failed for attribute %d of relation %u",
							 attno, seitem->relid);

					attno = get_attnum(relid_inh, attname);
					if (attno == InvalidAttrNumber)
						elog(ERROR, "cache lookup failed for attribute %s of relation %u",
							 attname, relid_inh);

					result = addEvalAttribute(result, relid_inh, false,
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

	/*
	 * EXPLAIN statement does not access any object.
	 */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;

	if (!pstmt->pgaceItem)
		return;

	Assert(IsA(pstmt->pgaceItem, List));
	selist = copyObject(pstmt->pgaceItem);

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

		selist = addEvalTriggerFunction(selist, rte->relid,
										pstmt->commandType);
	}

	/*
	 * Check SelinuxEvalItem
	 */
	foreach (l, selist)
		checkSelinuxEvalItem((SelinuxEvalItem *) lfirst(l));
}

/*
 * --------------------------------------------------------------
 * Process Utility hooks
 * --------------------------------------------------------------
 */

/*
 * sepgsqlProcessUtility
 *
 * This function is invoked from the head of ProcessUtility(), and
 * checks given DDL queries.
 * SE-PostgreSQL catch most of DDL actions on HeapTuple hooks, but
 * an exception is TRUNCATE statement.
 */
void
sepgsqlProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel)
{
	switch (nodeTag(parsetree))
	{
	case T_LoadStmt:
		{
			LoadStmt *load = (LoadStmt *)parsetree;
			sepgsqlCheckModuleInstallPerms(load->filename);
		}
		break;

	case T_CreateFdwStmt:
		{
			CreateFdwStmt *createFdw = (CreateFdwStmt *)parsetree;
			sepgsqlCheckModuleInstallPerms(createFdw->library);
		}
		break;

	case T_AlterFdwStmt:
		{
			AlterFdwStmt *alterFdw = (AlterFdwStmt *)parsetree;
			if (alterFdw->library)
				sepgsqlCheckModuleInstallPerms(alterFdw->library);
		}
		break;

	default:
		/*
		 * do nothing here
		 */
		break;
	}
}

/* ----------------------------------------------------------
 * COPY TO/COPY FROM statement hooks
 * ---------------------------------------------------------- */

/*
 * sepgsqlCopyTable
 *
 * This function checks permission on the target table and columns
 * of COPY statement. We don't place it at sepgsql/hooks.c because
 * it internally uses addEvalXXXX() interface statically declared.
 */
void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom)
{
	List	   *selist = NIL;
	ListCell   *l;

	/*
	 * on 'COPY FROM SELECT ...' cases, any checkings are done in select.c
	 */
	if (rel == NULL)
		return;

	/*
	 * no need to check non-table relation
	 */
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return;

	selist = addEvalRelation(selist, RelationGetRelid(rel), false,
							 isFrom ? DB_TABLE__INSERT : DB_TABLE__SELECT);
	foreach(l, attNumList)
	{
		AttrNumber	attnum = lfirst_int(l);

		selist = addEvalAttribute(selist, RelationGetRelid(rel), false, attnum,
								  isFrom ? DB_COLUMN__INSERT : DB_COLUMN__SELECT);
	}

	/*
	 * check call trigger function
	 */
	if (isFrom)
		selist = addEvalTriggerFunction(selist, RelationGetRelid(rel), CMD_INSERT);

	foreach (l, selist)
		checkSelinuxEvalItem((SelinuxEvalItem *) lfirst(l));
}

/*
 * sepgsqlCopyFile
 *
 * This function check permission whether the client can
 * read from/write to the given file.
 */
void sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom)
{
	security_context_t context;
	security_class_t tclass
		= sepgsqlFileObjectClass(fdesc, filename);

	if (fgetfilecon_raw(fdesc, &context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get context of %s", filename)));
	PG_TRY();
	{
		sepgsqlComputePermission(sepgsqlGetClientContext(),
								 context,
								 tclass,
								 isFrom ? FILE__READ : FILE__WRITE,
								 filename);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
}

/*
 * sepgsqlCopyToTuple
 *
 * This function check permission to read the given tuple.
 * If not allowed to read, it returns false to skip COPY TO
 * this tuple. In the result, any violated tuples are filtered
 * from the result of COPY TO, as if these are not exist.
 */
bool
sepgsqlCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	uint32		perms = SEPGSQL_PERMS_SELECT;

	/*
	 * for 'pg_largeobject'
	 */
	if (RelationGetRelid(rel) == LargeObjectRelationId)
	{
		ListCell   *l;

		foreach(l, attNumList)
		{
			AttrNumber	attnum = lfirst_int(l);

			if (attnum == Anum_pg_largeobject_data)
			{
				perms |= SEPGSQL_PERMS_READ;
				break;
			}
		}
	}
	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms, false);
}
