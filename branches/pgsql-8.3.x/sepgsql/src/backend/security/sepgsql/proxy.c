/*
 * src/backend/security/sepgsql/proxy.c
 *	  proxy routines to pick up all appeared columns, functions, ...
 *	  within given queries, and apply mandatory access controls.
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
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
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "executor/executor.h"
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
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * queryStack
 *
 * This structure represents a hierarchical relationshipt
 * between subqueries. When a Var node has positive varlevelsup,
 * it refers upper level Query structure using the chain of
 * queryStack.
 */
typedef struct queryStack
{
	struct queryStack *parent;
	Query	   *query;
} queryStack;

/*
 * sepgsqlWalkerContext
 *
 * This structure holds a context during analyzing a given query.
 * selist is a list of SEvalItemXXX objects to enumerate appared
 * tables, columns and functions. It is evaluated later, just
 * before executing query.
 * is_internal_use shows the current state whether the current
 * Node is chained with target list, or conditional clause.
 */
typedef struct sepgsqlWalkerContext
{
	List	   *selist;			/* List of SEvalItem */

	struct queryStack *qstack;

	bool		is_internal_use;
} sepgsqlWalkerContext;

/* static definitions for proxy functions */
static void proxyRteSubQuery(sepgsqlWalkerContext *swc, Query *query);

static bool sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc);

static void execVerifyQuery(List *selist);

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
	SEvalItemRelation *ser;

	ListCell   *l;

	foreach(l, selist)
	{
		ser = (SEvalItemRelation *) lfirst(l);
		if (IsA(ser, SEvalItemRelation)
			&& ser->relid == relid
			&& ser->inh == inh)
		{
			ser->perms |= perms;
			return selist;
		}
	}
	/*
	 * not found
	 */
	ser = makeNode(SEvalItemRelation);
	ser->perms = perms;
	ser->relid = relid;
	ser->inh = inh;

	return lappend(selist, ser);
}

static List *
addEvalRelationRTE(List *selist, RangeTblEntry *rte, uint32 perms)
{
	rte->pgaceTuplePerms |= (perms & DB_TABLE__USE ? SEPGSQL_PERMS_USE : 0);
	rte->pgaceTuplePerms |=
		(perms & DB_TABLE__SELECT ? SEPGSQL_PERMS_SELECT : 0);
	rte->pgaceTuplePerms |=
		(perms & DB_TABLE__INSERT ? SEPGSQL_PERMS_INSERT : 0);
	rte->pgaceTuplePerms |=
		(perms & DB_TABLE__UPDATE ? SEPGSQL_PERMS_UPDATE : 0);
	rte->pgaceTuplePerms |=
		(perms & DB_TABLE__DELETE ? SEPGSQL_PERMS_DELETE : 0);

	/*
	 * for 'pg_largeobject'
	 */
	if (rte->relid == LargeObjectRelationId && (perms & DB_TABLE__DELETE))
		rte->pgaceTuplePerms |= SEPGSQL_PERMS_WRITE;

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
	SEvalItemAttribute *sea;

	ListCell   *l;

	foreach(l, selist)
	{
		sea = (SEvalItemAttribute *) lfirst(l);
		if (IsA(sea, SEvalItemAttribute)
			&& sea->relid == relid
			&& sea->inh == inh
			&& sea->attno == attno)
		{
			sea->perms |= perms;
			return selist;
		}
	}
	/*
	 * not found
	 */
	sea = makeNode(SEvalItemAttribute);
	sea->perms = perms;
	sea->relid = relid;
	sea->inh = inh;
	sea->attno = attno;

	return lappend(selist, sea);
}

static List *
addEvalAttributeRTE(List *selist, RangeTblEntry *rte, AttrNumber attno, uint32 perms)
{
	uint32		t_perms = 0;

	/*
	 * for table:{ ... } permission
	 */
	t_perms |= (perms & DB_COLUMN__USE ? DB_TABLE__USE : 0);
	t_perms |= (perms & DB_COLUMN__SELECT ? DB_TABLE__SELECT : 0);
	t_perms |= (perms & DB_COLUMN__INSERT ? DB_TABLE__INSERT : 0);
	t_perms |= (perms & DB_COLUMN__UPDATE ? DB_TABLE__UPDATE : 0);
	selist = addEvalRelationRTE(selist, rte, t_perms);

	/*
	 * for 'security_context'
	 */
	if (attno == SecurityAttributeNumber
		&& (perms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT)))
		rte->pgaceTuplePerms |= SEPGSQL_PERMS_RELABELFROM;

	/*
	 * for 'pg_largeobject'
	 */
	if (rte->relid == LargeObjectRelationId)
	{
		if ((perms & DB_COLUMN__SELECT) && attno == Anum_pg_largeobject_data)
			rte->pgaceTuplePerms |= SEPGSQL_PERMS_READ;
		if ((perms & DB_COLUMN__UPDATE) && attno == Anum_pg_largeobject_data)
			rte->pgaceTuplePerms |= SEPGSQL_PERMS_WRITE;
	}

	return addEvalAttribute(selist, rte->relid, rte->inh, attno, perms);
}

/*
 * addEvalPgProc
 *
 * This function adds a given procedure into selist, if it is not
 * contained yet.
 */
static List *
addEvalPgProc(List *selist, Oid funcid, uint32 perms)
{
	SEvalItemProcedure *sep;

	ListCell   *l;

	foreach(l, selist)
	{
		sep = (SEvalItemProcedure *) lfirst(l);
		if (IsA(sep, SEvalItemProcedure)
			&& sep->funcid == funcid)
		{
			sep->perms |= perms;
			return selist;
		}
	}
	/*
	 * not found
	 */
	sep = makeNode(SEvalItemProcedure);
	sep->perms = perms;
	sep->funcid = funcid;

	return lappend(selist, sep);
}

/*
 * addEvalForeignKeyConstraint
 *
 * This function add special case handling for PK/FK constraints.
 * invoke trigger function requires to access rights for all attribute
 *
 */
static bool
triggerIsForeignKeyConstraint(Form_pg_trigger trigger)
{
	switch (trigger->tgfoid)
	{
	case F_RI_FKEY_CHECK_INS:
	case F_RI_FKEY_CHECK_UPD:
	case F_RI_FKEY_CASCADE_DEL:
	case F_RI_FKEY_CASCADE_UPD:
	case F_RI_FKEY_RESTRICT_DEL:
	case F_RI_FKEY_RESTRICT_UPD:
	case F_RI_FKEY_SETNULL_DEL:
	case F_RI_FKEY_SETNULL_UPD:
	case F_RI_FKEY_SETDEFAULT_DEL:
	case F_RI_FKEY_SETDEFAULT_UPD:
	case F_RI_FKEY_NOACTION_DEL:
	case F_RI_FKEY_NOACTION_UPD:
		return true;
	}
	return false;
}

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
 * addEvalTriggerAccess
 *
 * This function adds needed items into selist, to execute a trigger
 * function. At least, it requires permission set to execute a function
 * configured as a trigger, to select a table and whole of columns
 * because whole of a tuple is delivered to trigger functions.
 */
static List *
addEvalTriggerAccess(List *selist, Oid relid, bool is_inh, int cmdType)
{
	Relation	rel;
	SysScanDesc scan;
	ScanKeyData skey;
	HeapTuple	tuple;
	bool		checked = false;

	Assert(cmdType == CMD_INSERT
		   || cmdType == CMD_UPDATE
		   || cmdType == CMD_DELETE);

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
		 * add db_procedure:{execute} permission
		 */
		selist = addEvalPgProc(selist, trigForm->tgfoid,
							   DB_PROCEDURE__EXECUTE);

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

		if (!checked)
		{
			HeapTuple	reltup;
			Form_pg_class classForm;

			reltup = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);
			classForm = (Form_pg_class) GETSTRUCT(reltup);

			selist = addEvalRelation(selist, relid, false, DB_TABLE__SELECT);

			if (triggerIsForeignKeyConstraint(trigForm))
				selist = addEvalForeignKeyConstraint(selist, trigForm);
			else
				selist = addEvalAttribute(selist, relid, false,
										  0, DB_COLUMN__SELECT);
			ReleaseSysCache(reltup);

			checked = true;
		}
	}
	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	if (is_inh)
	{
		List	   *child_list = find_inheritance_children(relid);
		ListCell   *l;

		foreach(l, child_list)
			selist = addEvalTriggerAccess(selist, lfirst_oid(l),
										  is_inh, cmdType);
	}

	return selist;
}

/*
 * sepgsqlExprWalker
 *
 * This function walks on the given node tree recursively, to pick up 
 * all appeared tables, columns and functions. Their identifiers are
 * chained swc->selist, and evaluated later.
 *
 * walkVarHelper and walkOpExprHelper are used to simplify its
 * implementation. If swx->is_internal_use is true, it add a "use"
 * permission to be evaluate, or a "select" permission otherwise.
 */
static void
walkVarHelper(sepgsqlWalkerContext *swc, Var *var)
{
	RangeTblEntry *rte;
	queryStack *qstack;
	Query	   *query;
	int			lv;

	Assert(IsA(var, Var));

	/*
	 * resolve external Var reference
	 */
	qstack = swc->qstack;
	lv = var->varlevelsup;
	while (lv > 0)
	{
		Assert(!!qstack->parent);
		qstack = qstack->parent;
		lv--;
	}
	query = qstack->query;
	if (!query)
		elog(ERROR, "SELinux: could not walk T_Var node in this context");

	rte = rt_fetch(var->varno, query->rtable);
	Assert(IsA(rte, RangeTblEntry));

	if (rte->rtekind == RTE_RELATION)
	{
		/*
		 * table:{select/use} and column:{select/use}
		 */
		swc->selist = addEvalAttributeRTE(swc->selist, rte, var->varattno,
										  swc->is_internal_use
										  ? DB_COLUMN__USE : DB_COLUMN__SELECT);
	}
	else if (rte->rtekind == RTE_JOIN)
	{
		Node	   *node = list_nth(rte->joinaliasvars,
									var->varattno - 1);

		sepgsqlExprWalker(node, swc);
	}
}

static void
walkFuncExprHelper(sepgsqlWalkerContext *swc, Oid funcid, Node *args)
{
	swc->selist = addEvalPgProc(swc->selist, funcid,
								DB_PROCEDURE__EXECUTE);
	/*
	 * A malicious user defined function enables to leak given
	 * arguments to others, so we have to force {select} perms
	 * towards arguments on user defined functions.
	 * Here is an assumption built-in functions are not malicious.
	 */
	if (!fmgr_isbuiltin(funcid))
	{
		bool is_internal_use_backup = swc->is_internal_use;

		swc->is_internal_use = 0;
		sepgsqlExprWalker(args, swc);
		swc->is_internal_use = is_internal_use_backup;
	}
	else
		sepgsqlExprWalker(args, swc);
}

static void
walkOpExprHelper(sepgsqlWalkerContext *swc, Oid opid, Node *args)
{
	HeapTuple	tuple;
	Oid			oprcode;
	Oid			oprrest;
	Oid			oprjoin;

	tuple = SearchSysCache(OPEROID, ObjectIdGetDatum(opid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for operator %u", opid);

	oprcode = ((Form_pg_operator) GETSTRUCT(tuple))->oprcode;
	oprrest = ((Form_pg_operator) GETSTRUCT(tuple))->oprrest;
	oprjoin = ((Form_pg_operator) GETSTRUCT(tuple))->oprjoin;

	ReleaseSysCache(tuple);

	walkFuncExprHelper(swc, oprcode, args);
	if (OidIsValid(oprrest))
		walkFuncExprHelper(swc, oprrest, args);
	if (OidIsValid(oprjoin))
		walkFuncExprHelper(swc, oprjoin, args);
}

static bool
sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc)
{
	if (node == NULL)
		return false;
	else if (IsA(node, Var))
		walkVarHelper(swc, (Var *) node);
	else if (IsA(node, FuncExpr))
	{
		FuncExpr *ex = (FuncExpr *) node;

		walkFuncExprHelper(swc, ex->funcid, (Node *)ex->args);
		return false;
	}
	else if (IsA(node, Aggref))
	{
		Aggref *ex = (Aggref *) node;

		walkFuncExprHelper(swc, ex->aggfnoid, (Node *)ex->args);
		return false;
	}
	else if (IsA(node, OpExpr) ||
			 IsA(node, DistinctExpr) ||
			 IsA(node, NullIfExpr))
	{
		OpExpr *ex = (OpExpr *) node;

		walkOpExprHelper(swc, ex->opno, (Node *)ex->args);
		return false;
	}
	else if (IsA(node, ScalarArrayOpExpr))
	{
		ScalarArrayOpExpr *ex = (ScalarArrayOpExpr *) node;

		walkOpExprHelper(swc, ex->opno, (Node *)ex->args);
		return false;
	}
	else if (IsA(node, Query))
	{
		/*
		 * Subquery within SubLink or CommonTableExpr
		 */
		proxyRteSubQuery(swc, (Query *) node);
	}
	else if (IsA(node, ArrayCoerceExpr))
	{
		ArrayCoerceExpr *ex = (ArrayCoerceExpr *) node;

		if (OidIsValid(ex->elemfuncid))
		{
			walkFuncExprHelper(swc, ex->elemfuncid, (Node *)ex->arg);
			return false;
		}
	}
	else if (IsA(node, RowCompareExpr))
	{
		RowCompareExpr *ex = (RowCompareExpr *) node;
		ListCell *l, *r;
		int index = 0;

		Assert(list_length(ex->opnos) == list_length(ex->largs));
		Assert(list_length(ex->opnos) == list_length(ex->rargs));

		forboth(l, ex->largs, r, ex->rargs)
		{
			List *lst = list_make2(lfirst(l), lfirst(r));

			walkOpExprHelper(swc, list_nth_oid(ex->opnos, index++), (Node *)lst);
			list_free(lst);
		}
		return false;
	}
	else if (IsA(node, SortClause) ||
			 IsA(node, GroupClause))
	{
		SortClause *ex = (SortClause *) node;
		Query *query = swc->qstack->query;
		TargetEntry *tle
			= get_sortgroupref_tle(ex->tleSortGroupRef, query->targetList);

		Assert(IsA(tle, TargetEntry));
		walkOpExprHelper(swc, ex->sortop, (Node *)tle->expr);

		return false;
	}

	return expression_tree_walker(node, sepgsqlExprWalker, (void *) swc);
}

static bool
sepgsqlExprWalkerFlags(Node *node, sepgsqlWalkerContext *swc, bool is_internal_use)
{
	bool		saved_is_internal_use = swc->is_internal_use;
	bool		rc;

	swc->is_internal_use = is_internal_use;
	rc = sepgsqlExprWalker(node, swc);
	swc->is_internal_use = saved_is_internal_use;

	return rc;
}

/*
 * proxyJoinTree
 *
 * It appends SEvalItem of WHERE/JOIN ON clause, nodes in VALUE
 * clause or function which returns a relation, or invokes
 * proxyRteSubQuery recursively.
 */
static void
proxyJoinTree(sepgsqlWalkerContext *swc, Node *node)
{
	Query	   *query = swc->qstack->query;

	if (node == NULL)
		return;

	if (IsA(node, RangeTblRef))
	{
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

		Assert(IsA(rte, RangeTblEntry));

		switch (rte->rtekind)
		{
		case RTE_RELATION:
			if (rtr->rtindex != query->resultRelation)
			{
				swc->selist = addEvalRelationRTE(swc->selist, rte,
												 DB_TABLE__SELECT);
			}
			break;

		case RTE_SUBQUERY:
			proxyRteSubQuery(swc, rte->subquery);
			break;

		case RTE_FUNCTION:
			sepgsqlExprWalkerFlags(rte->funcexpr, swc, false);
			break;

		case RTE_VALUES:
			sepgsqlExprWalkerFlags((Node *) rte->values_lists, swc, false);
			break;

		default:
			break;
		}
	}
	else if (IsA(node, FromExpr))
	{
		FromExpr *from = (FromExpr *) node;
		ListCell *l;

		sepgsqlExprWalkerFlags(from->quals, swc, true);
		foreach(l, from->fromlist)
			proxyJoinTree(swc, lfirst(l));
	}
	else if (IsA(node, JoinExpr))
	{
		JoinExpr *join = (JoinExpr *) node;

		sepgsqlExprWalkerFlags(join->quals, swc, true);
		proxyJoinTree(swc, join->larg);
		proxyJoinTree(swc, join->rarg);
	}
	else
	{
		elog(ERROR, "SELinux: unexpected node type (%d)", nodeTag(node));
	}
}

/*
 * proxySetOperations
 *
 * It walks on a query tree recursively when set operations
 * (UNION, INTERSECT, EXCEPT) are used.
 *
 */
static void
proxySetOperations(sepgsqlWalkerContext *swc, Node *node)
{
	Query	   *query = swc->qstack->query;

	if (node == NULL)
		return;

	if (IsA(node, RangeTblRef))
	{
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

		Assert(IsA(rte, RangeTblEntry)
			   && rte->rtekind == RTE_SUBQUERY);
		proxyRteSubQuery(swc, rte->subquery);
	}
	else if (IsA(node, SetOperationStmt))
	{
		SetOperationStmt *sop = (SetOperationStmt *) node;

		proxySetOperations(swc, sop->larg);
		proxySetOperations(swc, sop->rarg);
	}
	else
	{
		elog(ERROR, "SELinux: unexpected node (%d)", nodeTag(node));
	}
}

/*
 * proxyRteSubQuery
 *
 * It walks on the given DML Query to enumerate all appeared tables,
 * columns and functions which include implementations of operator.
 * While its walking, it generates a list of SEvalItemXXXX object
 * to be evaluated later, and marks required permission on
 * RangeTblEntry->pgaceTuplePerms. The swc->selist is copied to
 * PlannedStmt->pgaceItem and evaluated on the hook invoked from
 * the executor. RangeTblEntry->pgaceTuplePerms is copied to 
 * Scan->pgaceTuplePerms and it can be refered at sepgsqlExecScan()
 * hook to apply tuple-level access controls.
 */
static void
proxyRteSubQuery(sepgsqlWalkerContext *swc, Query *query)
{
	CmdType		cmdType = query->commandType;
	RangeTblEntry *rte = NULL;
	struct queryStack qsData;
	ListCell   *l;

	/*
	 * push a query to queryStack
	 */
	qsData.parent = swc->qstack;
	qsData.query = query;
	swc->qstack = &qsData;

	if (cmdType != CMD_DELETE)
	{
		foreach(l, query->targetList)
		{
			TargetEntry *tle = lfirst(l);
			bool is_security = false;

			Assert(IsA(tle, TargetEntry));

			if (tle->resjunk &&
				tle->resname &&
				strcmp(tle->resname, SECURITY_SYSATTR_NAME) == 0)
				is_security = true;

			/*
			 * contents of junk target is not exposed to users,
			 * so it should be evaluated as "use" permission.
			 */
			if (tle->resjunk && !is_security)
			{
				sepgsqlExprWalkerFlags((Node *) tle->expr, swc, true);
				continue;
			}

			sepgsqlExprWalkerFlags((Node *) tle->expr, swc, false);

			if (cmdType != CMD_SELECT)
			{
				AttrNumber attno
					= (is_security ? SecurityAttributeNumber : tle->resno);
				uint32 perms
					= (cmdType == CMD_UPDATE ? DB_COLUMN__UPDATE : DB_COLUMN__INSERT);

				rte = rt_fetch(query->resultRelation, query->rtable);
				Assert(IsA(rte, RangeTblEntry));

				swc->selist = addEvalAttributeRTE(swc->selist, rte, attno, perms);
			}
		}
	}
	else
	{
		/*
		 * NOTE: column level checks are not necessary for normal DELETE
		 */
		rte = rt_fetch(query->resultRelation, query->rtable);
		Assert(IsA(rte, RangeTblEntry));

		swc->selist = addEvalRelationRTE(swc->selist, rte, DB_TABLE__DELETE);
	}

	proxyJoinTree(swc, (Node *) query->jointree);

	sepgsqlExprWalkerFlags((Node *) query->returningList, swc, false);
	sepgsqlExprWalkerFlags((Node *) query->havingQual, swc, true);
	sepgsqlExprWalkerFlags((Node *) query->sortClause, swc, true);
	sepgsqlExprWalkerFlags((Node *) query->groupClause, swc, true);

	/*
	 * permission mark on the UNION/INTERSECT/EXCEPT
	 */
	proxySetOperations(swc, query->setOperations);

	/*
	 * pop a query to queryStack
	 */
	swc->qstack = qsData.parent;
}

/*
 * sepgsqlProxyQuery
 *
 * This function is invoked just after the given queries rewritten
 * by the query rewriter. It invokes proxyRteSubQuery() for any
 * DML queries to pick up all appeared database object and stores
 * the list of them into Query->pgaceItem to evaluate later.
 *
 * It does not do anything for DDL queries because it is processed
 * on sepgsqlProcessUtility() hook.
 */
List *
sepgsqlProxyQuery(List *queryList)
{
	List	   *newList = NIL;
	ListCell   *l;

	foreach (l, queryList)
	{
		Query  *query = (Query *) lfirst(l);

		Assert(IsA(query, Query));

		switch (query->commandType)
		{
		case CMD_SELECT:
		case CMD_UPDATE:
		case CMD_INSERT:
		case CMD_DELETE:
			{
				sepgsqlWalkerContext swcData;

				memset(&swcData, 0, sizeof(swcData));

				proxyRteSubQuery(&swcData, query);
				query->pgaceItem = (Node *) swcData.selist;

				newList = lappend(newList, query);
			}
			break;
		default:
			newList = lappend(newList, query);
			break;
		}
	}

	return newList;
}

/*
 * sepgsqlEvaluateParams
 *
 * It checks permissions to execute functions just before
 * parameter list is generated.
 */
void
sepgsqlEvaluateParams(List *params)
{
	sepgsqlWalkerContext swcData;

	queryStack	qsData;

	memset(&qsData, 0, sizeof(queryStack));
	memset(&swcData, 0, sizeof(sepgsqlWalkerContext));
	swcData.qstack = &qsData;

	sepgsqlExprWalkerFlags((Node *) params, &swcData, false);

	execVerifyQuery(swcData.selist);
}

/*
 * verityXXXX()
 *
 * These functions are invoked from execVerifyQuery, to evaluate
 * SEvalItemXXXX objects generated at sepgsqlProxyQuery().
 */

/*
 * verifyPgClassPerms
 *
 * It evaluates SEvalItemRelation object to access tables.
 */
static void
verifyPgClassPerms(Oid relid, bool inh, uint32 perms)
{
	HeapTuple	tuple;

	/*
	 * prevent to modify pg_security directly
	 */
	if (relid == SecurityRelationId
		&& (perms & (DB_TABLE__UPDATE | DB_TABLE__INSERT | DB_TABLE__DELETE)))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: user cannot modify pg_security directly")));

	/*
	 * check table:{required permissions}
	 */
	tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation: %u", relid);

	if (((Form_pg_class) GETSTRUCT(tuple))->relkind == RELKIND_RELATION)
	{
		sepgsqlClientHasPermission(HeapTupleGetSecurity(tuple),
								   SECCLASS_DB_TABLE,
								   (access_vector_t) perms,
								   sepgsqlTupleName(RelationRelationId, tuple));
	}
	ReleaseSysCache(tuple);
}

/*
 * verifyPgAttributePerms
 *
 * It evaluates SEvalItemAttribute to access columns.
 */
static void
verifyPgAttributePerms(Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	Form_pg_class clsForm;
	HeapTuple	tuple;

	tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation: %u", relid);

	clsForm = (Form_pg_class) GETSTRUCT(tuple);
	if (clsForm->relkind != RELKIND_RELATION)
	{
		ReleaseSysCache(tuple);
		return;
	}
	ReleaseSysCache(tuple);

	/*
	 * 2. verify column perms
	 */
	if (attno == 0)
	{
		/*
		 * RECORD type permission check
		 */
		Relation	rel;
		ScanKeyData skey;
		SysScanDesc scan;

		ScanKeyInit(&skey,
					Anum_pg_attribute_attrelid,
					BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));

		rel = heap_open(AttributeRelationId, AccessShareLock);
		scan = systable_beginscan(rel, AttributeRelidNumIndexId,
								  true, SnapshotNow, 1, &skey);
		while ((tuple = systable_getnext(scan)) != NULL)
		{
			Form_pg_attribute attForm = (Form_pg_attribute) GETSTRUCT(tuple);

			if (attForm->attisdropped || attForm->attnum < 1)
				continue;

			sepgsqlClientHasPermission(HeapTupleGetSecurity(tuple),
									   SECCLASS_DB_COLUMN,
									   perms,
									   sepgsqlTupleName(AttributeRelationId, tuple));
		}
		systable_endscan(scan);
		heap_close(rel, AccessShareLock);

		return;
	}
	/*
	 * check required column's permission 
	 */
	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attno), 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %u",
			 attno, relid);

	sepgsqlClientHasPermission(HeapTupleGetSecurity(tuple),
							   SECCLASS_DB_COLUMN,
							   perms,
							   sepgsqlTupleName(AttributeRelationId, tuple));
	ReleaseSysCache(tuple);
}

/*
 * verifyPgProcedurePerms
 *
 * It evaluates SEvalItemProcedure object to access tables.
 */
static void
verifyPgProcPerms(Oid funcid, uint32 perms)
{
	HeapTuple	tuple;
	security_context_t ncon;

	tuple = SearchSysCache(PROCOID, ObjectIdGetDatum(funcid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure %d", funcid);
	/*
	 * check domain transition
	 */
	ncon = sepgsqlClientCreateContext(HeapTupleGetSecurity(tuple),
									  SECCLASS_PROCESS);
	if (strcmp(sepgsqlGetClientContext(), ncon))
	{
		perms |= DB_PROCEDURE__ENTRYPOINT;

		sepgsqlComputePermission(sepgsqlGetClientContext(),
								 ncon,
								 SECCLASS_PROCESS,
								 PROCESS__TRANSITION,
								 NULL);
	}
	pfree(ncon);

	/*
	 * check procedure executiong permission
	 */
	sepgsqlClientHasPermission(HeapTupleGetSecurity(tuple),
							   SECCLASS_DB_PROCEDURE,
							   perms,
							   sepgsqlTupleName(ProcedureRelationId, tuple));
	ReleaseSysCache(tuple);
}

/*
 * expandSEvalItemInheritance
 *
 * When a request to table/column is inheritable, we have to expand
 * the target to child relations, because accessing a column within
 * parent table also means accessing a column within child relation
 * in same time.
 *
 * For example, when t2 and t3 inherits t1, we have to check permission
 * on t2.x and t3.x for the request to t1.x.
 * It is impossible to be done before, because we have a chance to
 * change inheritance relationships between PREPARE and EXECUTE.
 * So, we have to check it in execution phase.
 */
static List *
expandRelationInheritance(List *selist, Oid relid, uint32 perms)
{
	List	   *inherits = find_all_inheritors(relid);
	ListCell   *l;

	foreach(l, inherits)
		selist = addEvalRelation(selist, lfirst_oid(l), false, perms);

	return selist;
}

static List *
expandAttributeInheritance(List *selist, Oid relid, char *attname,
						   uint32 perms)
{
	List	   *inherits = find_all_inheritors(relid);
	ListCell   *l;

	foreach(l, inherits)
	{
		Form_pg_attribute attr;

		HeapTuple	tuple;

		if (!attname)
		{
			selist = addEvalAttribute(selist, lfirst_oid(l), false, 0, perms);
			continue;
		}

		tuple = SearchSysCacheAttName(lfirst_oid(l), attname);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR,
				 "SELinux: cache lookup failed for attribute %s of relation %u",
				 attname, lfirst_oid(l));

		attr = (Form_pg_attribute) GETSTRUCT(tuple);
		selist = addEvalAttribute(selist, lfirst_oid(l), false,
								  attr->attnum, perms);

		ReleaseSysCache(tuple);
	}

	return selist;
}

static List *
expandSEvalItemInheritance(List *selist)
{
	SEvalItemRelation *ser;
	SEvalItemAttribute *sea;
	List	   *result = NIL;
	ListCell   *l;

	foreach(l, selist)
	{
		Node	   *node = lfirst(l);

		result = lappend(result, node);
		switch (nodeTag(node))
		{
			case T_SEvalItemRelation:
				ser = (SEvalItemRelation *) node;
				if (ser->inh)
				{
					ser->inh = false;
					result = expandRelationInheritance(result,
													   ser->relid, ser->perms);
				}
				break;

			case T_SEvalItemAttribute:
				sea = (SEvalItemAttribute *) node;
				if (sea->inh)
				{
					Form_pg_attribute attr;
					HeapTuple	tuple;

					sea->inh = false;
					if (sea->attno == 0)
					{
						result = expandAttributeInheritance(result,
															sea->relid,
															NULL, sea->perms);
						break;
					}

					tuple = SearchSysCache(ATTNUM,
										   ObjectIdGetDatum(sea->relid),
										   Int16GetDatum(sea->attno), 0, 0);
					if (!HeapTupleIsValid(tuple))
						elog(ERROR,
							 "SELinux: cache lookup failed for attribute %d of relation %u",
							 sea->attno, sea->relid);
					attr = (Form_pg_attribute) GETSTRUCT(tuple);

					result = expandAttributeInheritance(result,
														sea->relid,
														NameStr(attr->attname),
														sea->perms);
					ReleaseSysCache(tuple);
				}
				break;

			case T_SEvalItemProcedure:
				/*
				 * do nothing
				 */
				break;

			default:
				elog(ERROR, "SELinux: Invalid node type (%d) in SEvalItemList",
					 nodeTag(node));
				break;
		}
	}
	return result;
}

/*
 * execVerifyQuery
 *
 * This function scans the given list, and invokes proper function
 * to evaluate it.
 */
static void
execVerifyQuery(List *selist)
{
	SEvalItemRelation *ser;
	SEvalItemAttribute *sea;
	SEvalItemProcedure *sep;
	ListCell   *l;

	foreach(l, selist)
	{
		Node	   *node = lfirst(l);

		switch (nodeTag(node))
		{
			case T_SEvalItemRelation:
				ser = (SEvalItemRelation *) node;
				verifyPgClassPerms(ser->relid, ser->inh, ser->perms);
				break;

			case T_SEvalItemAttribute:
				sea = (SEvalItemAttribute *) node;
				verifyPgAttributePerms(sea->relid, sea->inh, sea->attno,
									   sea->perms);
				break;

			case T_SEvalItemProcedure:
				sep = (SEvalItemProcedure *) node;
				verifyPgProcPerms(sep->funcid, sep->perms);
				break;

			default:
				elog(ERROR, "SELinux: Invalid node type (%d) in SEvalItemList",
					 nodeTag(node));
				break;
		}
	}
}

/*
 * sepgsqlVerifyQuery
 *
 * This function is invoked at the head of ExecutorStart, to evaluate
 * permissions to access appeared object within the given query.
 * Query->pgaceItem is a list of SEvalItemXXXX objects generated in
 * previous phase, and it is copied to PlannedStmt->pgaceItem in the
 * optimizer.
 * sepgsqlVerifyQuery expand relations/columns and append permissions
 * to execute trigger functions, if necessary.
 */
void
sepgsqlVerifyQuery(PlannedStmt *pstmt, int eflags)
{
	RangeTblEntry *rte;
	List	   *selist;
	ListCell   *l;

	/*
	 * EXPLAIN statement does not access any object.
	 */
	if ((eflags & EXEC_FLAG_EXPLAIN_ONLY) != 0)
		return;
	if (!pstmt->pgaceItem)
		return;

	Assert(IsA(pstmt->pgaceItem, List));
	selist = copyObject(pstmt->pgaceItem);

	/*
	 * expand table inheritances
	 */
	selist = expandSEvalItemInheritance(selist);

	/*
	 * add checks for access via trigger function
	 */
	foreach(l, pstmt->resultRelations)
	{
		Index		rindex = lfirst_int(l);

		rte = rt_fetch(rindex, pstmt->rtable);
		Assert(IsA(rte, RangeTblEntry));

		selist = addEvalTriggerAccess(selist, rte->relid, rte->inh,
									  pstmt->commandType);
	}
	execVerifyQuery(selist);
}

/*
 * --------------------------------------------------------------
 * Process Utility hooks
 * --------------------------------------------------------------
 */

/*
 * checkTruncateStmt
 *
 * This function checks permissions of tuples within the given
 * tables before TRUNCATE them. Because its meanings are same
 * as unconditional DELETE logically, SE-PostgreSQL attempt to
 * apply same permission for them operation.
 * If there is a violated tuple at most, it stops to execute 
 * TRUNCATE and abort current trunsaction.
 */
static void
checkTruncateStmt(TruncateStmt *stmt)
{
	Relation	rel;
	HeapScanDesc scan;
	HeapTuple	tuple;
	List	   *relidList = NIL;
	ListCell   *l;

	foreach(l, stmt->relations)
	{
		RangeVar   *rv = lfirst(l);

		relidList = lappend_oid(relidList, RangeVarGetRelid(rv, false));
	}

	if (stmt->behavior == DROP_CASCADE)
	{
		relidList = list_concat(relidList, heap_truncate_find_FKs(relidList));
	}

	foreach(l, relidList)
	{
		Oid			relid = lfirst_oid(l);

		/*
		 * 1. db_table:{delete}
		 */
		tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);
		sepgsqlClientHasPermission(HeapTupleGetSecurity(tuple),
								   SECCLASS_DB_TABLE,
								   DB_TABLE__DELETE,
								   sepgsqlTupleName(RelationRelationId, tuple));
		ReleaseSysCache(tuple);

		/*
		 * 2. db_tuple:{delete}
		 */
		rel = heap_open(relid, AccessShareLock);
		scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			sepgsqlCheckTuplePerms(rel, tuple, NULL,
								   SEPGSQL_PERMS_DELETE, true);
		}
		heap_endscan(scan);
		heap_close(rel, AccessShareLock);
	}
}

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
		case T_TruncateStmt:
			checkTruncateStmt((TruncateStmt *) parsetree);
			break;
		default:
			/*
			 * do nothing
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
		selist = addEvalTriggerAccess(selist, RelationGetRelid(rel),
									  false, CMD_INSERT);

	execVerifyQuery(selist);
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
		= sepgsqlProperFileObjectClass(fdesc, filename);

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
