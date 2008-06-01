/*
 * src/backend/security/sepgsqlProxy.c
 *   SE-PostgreSQL Query Proxy function to walk on query node tree
 *   and append tuple filter.
 *
 * Copyright KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "catalog/heap.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "nodes/makefuncs.h"
#include "nodes/readfuncs.h"
#include "nodes/security.h"
#include "optimizer/clauses.h"
#include "optimizer/plancat.h"
#include "optimizer/prep.h"
#include "parser/parse_relation.h"
#include "parser/parse_target.h"
#include "parser/parsetree.h"
#include "security/pgace.h"
#include "security/sepgsql.h"
#include "storage/lock.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

typedef struct queryStack {
	struct queryStack *parent;
	Query *query;
} queryStack;

typedef struct sepgsqlWalkerContext {
	/* List of SEvalItem */
	List *selist;

	struct queryStack *qstack;

	/* flags */
	bool is_internal_use;
} sepgsqlWalkerContext;

/* static definitions for proxy functions */
static void proxyRteSubQuery(sepgsqlWalkerContext *swc, Query *query);
static bool sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc);
static void execVerifyQuery(List *selist);

/* -----------------------------------------------------------
 * addEvalXXXX -- add evaluation items into Query->SEvalItemList.
 * Those are used for execution phase.
 * ----------------------------------------------------------- */
static List *addEvalRelation(List *selist, Oid relid, bool inh, uint32 perms)
{
	SEvalItemRelation *ser;
	ListCell *l;

	foreach (l, selist)
	{
		ser = (SEvalItemRelation *) lfirst(l);
		if (IsA(ser, SEvalItemRelation)
			&& ser->relid == relid && ser->inh == inh)
		{
			ser->perms |= perms;
			return selist;
		}
	}
	/* not found */
	ser = makeNode(SEvalItemRelation);
	ser->perms = perms;
	ser->relid = relid;
	ser->inh = inh;

	return lappend(selist, ser);
}

static List *addEvalRelationRTE(List *selist, RangeTblEntry *rte, uint32 perms)
{
	rte->pgaceTuplePerms |= (perms & DB_TABLE__USE    ? SEPGSQL_PERMS_USE : 0);
	rte->pgaceTuplePerms |= (perms & DB_TABLE__SELECT ? SEPGSQL_PERMS_SELECT : 0);
	rte->pgaceTuplePerms |= (perms & DB_TABLE__INSERT ? SEPGSQL_PERMS_INSERT : 0);
	rte->pgaceTuplePerms |= (perms & DB_TABLE__UPDATE ? SEPGSQL_PERMS_UPDATE : 0);
	rte->pgaceTuplePerms |= (perms & DB_TABLE__DELETE ? SEPGSQL_PERMS_DELETE : 0);

	/* for 'pg_largeobject' */
	if (rte->relid == LargeObjectRelationId && (perms & DB_TABLE__DELETE))
		rte->pgaceTuplePerms |= SEPGSQL_PERMS_WRITE;

	return addEvalRelation(selist, rte->relid, rte->inh, perms);
}

static List *addEvalAttribute(List *selist, Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	SEvalItemAttribute *sea;
	ListCell *l;

	foreach (l, selist) {
		sea = (SEvalItemAttribute *) lfirst(l);
		if (IsA(sea, SEvalItemAttribute)
			&& sea->relid == relid && sea->inh == inh && sea->attno == attno)
		{
			sea->perms |= perms;
			return selist;
		}
	}
	/* not found */
	sea = makeNode(SEvalItemAttribute);
	sea->perms = perms;
	sea->relid = relid;
	sea->inh = inh;
	sea->attno = attno;

	return lappend(selist, sea);
}

static List *addEvalAttributeRTE(List *selist, RangeTblEntry *rte, AttrNumber attno, uint32 perms)
{
	uint32 t_perms = 0;

	/* for table:{ ... } permission */
	t_perms |= (perms & DB_COLUMN__USE    ? DB_TABLE__USE : 0);
	t_perms |= (perms & DB_COLUMN__SELECT ? DB_TABLE__SELECT : 0);
	t_perms |= (perms & DB_COLUMN__INSERT ? DB_TABLE__INSERT : 0);
	t_perms |= (perms & DB_COLUMN__UPDATE ? DB_TABLE__UPDATE : 0);
	selist = addEvalRelationRTE(selist, rte, t_perms);

	/* for 'security_context' */
	if (attno == SecurityAttributeNumber
		&& (perms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT)))
		rte->pgaceTuplePerms |= SEPGSQL_PERMS_RELABELFROM;

	/* for 'pg_largeobject' */
	if (rte->relid == LargeObjectRelationId) {
		if ((perms & DB_COLUMN__SELECT) && attno == Anum_pg_largeobject_data)
			rte->pgaceTuplePerms |= SEPGSQL_PERMS_READ;
		if ((perms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT)) && attno > 0)
			rte->pgaceTuplePerms |= SEPGSQL_PERMS_WRITE;
	}

	return addEvalAttribute(selist, rte->relid, rte->inh, attno, perms);
}

static List *addEvalPgProc(List *selist, Oid funcid, uint32 perms)
{
	SEvalItemProcedure *sep;
	ListCell *l;

	foreach (l, selist) {
		sep = (SEvalItemProcedure *) lfirst(l);
		if (IsA(sep, SEvalItemProcedure)
			&& sep->funcid == funcid)
		{
			sep->perms |= perms;
			return selist;
		}
	}
	/* not found */
	sep = makeNode(SEvalItemProcedure);
	sep->perms = perms;
	sep->funcid = funcid;

	return lappend(selist, sep);
}

static List *addEvalTriggerAccess(List *selist, Oid relid, bool is_inh, int cmdType)
{
	Relation rel;
	SysScanDesc scan;
	ScanKeyData skey;
	HeapTuple tuple;
	bool checked = false;

	Assert(cmdType == CMD_INSERT || cmdType == CMD_UPDATE || cmdType == CMD_DELETE);

	rel = heap_open(TriggerRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				Anum_pg_trigger_tgrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
	scan = systable_beginscan(rel, TriggerRelidNameIndexId,
							  true, SnapshotNow, 1, &skey);
	while (HeapTupleIsValid((tuple = systable_getnext(scan)))) {
		Form_pg_trigger trigForm = (Form_pg_trigger) GETSTRUCT(tuple);

		if (!trigForm->tgenabled)
			continue;

		if ((cmdType == CMD_INSERT && !TRIGGER_FOR_INSERT(trigForm->tgtype))
			|| (cmdType == CMD_UPDATE && !TRIGGER_FOR_UPDATE(trigForm->tgtype))
			|| (cmdType == CMD_DELETE && !TRIGGER_FOR_DELETE(trigForm->tgtype)))
			continue;

		/* per STATEMENT trigger cannot refer whole of a tuple */
		if (!TRIGGER_FOR_ROW(trigForm->tgtype))
			continue;

		/* BEFORE-ROW-INSERT trigger cannot refer whole of a tuple */
		if (TRIGGER_FOR_BEFORE(trigForm->tgtype) && TRIGGER_FOR_INSERT(trigForm->tgtype))
			continue;

		selist = addEvalPgProc(selist, trigForm->tgfoid, DB_PROCEDURE__EXECUTE);
		if (!checked) {
			HeapTuple reltup;
			Form_pg_class classForm;
			AttrNumber attnum;

			reltup = SearchSysCache(RELOID,
									ObjectIdGetDatum(relid),
									0, 0, 0);
			classForm = (Form_pg_class) GETSTRUCT(reltup);

			selist = addEvalRelation(selist, relid, false, DB_TABLE__SELECT);
			for (attnum = FirstLowInvalidHeapAttributeNumber + 1; attnum <= 0; attnum++) {
				if (attnum == ObjectIdAttributeNumber && !classForm->relhasoids)
					continue;
				selist = addEvalAttribute(selist, relid, false, attnum, DB_COLUMN__SELECT);
			}
			ReleaseSysCache(reltup);

			checked = true;
		}
	}
	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	if (is_inh) {
		List *child_list = find_inheritance_children(relid);
		ListCell *l;

		foreach(l, child_list)
			selist = addEvalTriggerAccess(selist, lfirst_oid(l), is_inh, cmdType);
	}

	return selist;
}

/* *******************************************************************************
 * sepgsqlExprWalker() -- walk on expression tree recursively to pick up and to construct
 * a SEvalItem list related to expression node.
 * It is evaluated at later phase.
 * *******************************************************************************/

static void walkVarHelper(sepgsqlWalkerContext *swc, Var *var)
{
	RangeTblEntry *rte;
	queryStack *qstack;
	Query *query;
	int lv;

	Assert(IsA(var, Var));
	/* resolve external Var reference */
	qstack = swc->qstack;
	lv = var->varlevelsup;
	while (lv > 0) {
		Assert(!!qstack->parent);
		qstack = qstack->parent;
		lv--;
	}
	query = qstack->query;
	if (!query)
		elog(ERROR, "could not walk T_Var node in this context");

	rte = rt_fetch(var->varno, query->rtable);
	Assert(IsA(rte, RangeTblEntry));

	if (rte->rtekind == RTE_RELATION)
	{
		/* table:{select/use} and column:{select/use} */
		swc->selist = addEvalAttributeRTE(swc->selist, rte, var->varattno,
										  swc->is_internal_use
										  ? DB_COLUMN__USE : DB_COLUMN__SELECT);
	}
	else if (rte->rtekind == RTE_JOIN)
	{
		Node *node = list_nth(rte->joinaliasvars, var->varattno - 1);
		sepgsqlExprWalker(node, swc);
	}
}

static void walkOpExprHelper(sepgsqlWalkerContext *swc, Oid opid)
{
	HeapTuple tuple;
	Form_pg_operator oprform;

	tuple = SearchSysCache(OPEROID,
						   ObjectIdGetDatum(opid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for operator %u", opid);
	oprform = (Form_pg_operator) GETSTRUCT(tuple);

	swc->selist = addEvalPgProc(swc->selist, oprform->oprcode, DB_PROCEDURE__EXECUTE);
	/* NOTE: opr->oprrest and opr->oprjoin are internal use only
	 * and have no effect onto the data references, so we don't
	 * apply any checkings for them.
	 */
	ReleaseSysCache(tuple);
}

static bool sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc)
{
	if (node == NULL)
		return false;

	switch (nodeTag(node)) {
	case T_Var:
		walkVarHelper(swc, (Var *) node);
		break;

	case T_FuncExpr:
		swc->selist = addEvalPgProc(swc->selist,
									((FuncExpr *) node)->funcid,
									DB_PROCEDURE__EXECUTE);
		break;

	case T_Aggref:
		swc->selist = addEvalPgProc(swc->selist,
									((Aggref *) node)->aggfnoid,
									DB_PROCEDURE__EXECUTE);
		break;

	case T_OpExpr:
	case T_DistinctExpr:	/* typedef of OpExpr */
	case T_NullIfExpr:		/* typedef of OpExpr */
		walkOpExprHelper(swc, ((OpExpr *) node)->opno);
		break;

	case T_ScalarArrayOpExpr:
		walkOpExprHelper(swc, ((ScalarArrayOpExpr *) node)->opno);
		break;

	case T_SubLink: {
		SubLink *slink = (SubLink *) node;

		Assert(IsA(slink->subselect, Query));
		proxyRteSubQuery(swc, (Query *) slink->subselect);
		break;
	}
	case T_ArrayCoerceExpr: {
		ArrayCoerceExpr *ace = (ArrayCoerceExpr *) node;

		if (ace->elemfuncid != InvalidOid)
			swc->selist = addEvalPgProc(swc->selist,
										ace->elemfuncid,
										DB_PROCEDURE__EXECUTE);
		break;
	}
	case T_RowCompareExpr: {
		RowCompareExpr *rce = (RowCompareExpr *) node;
		ListCell *l;

		foreach (l, rce->opnos)
			walkOpExprHelper(swc, lfirst_oid(l));
		break;
	}
	default:
		/* do nothing here */
		break;
	}

	return expression_tree_walker(node, sepgsqlExprWalker, (void *) swc);
}

static bool sepgsqlExprWalkerFlags(Node *node, sepgsqlWalkerContext *swc, bool is_internal_use)
{
	bool saved_is_internal_use = swc->is_internal_use;
	bool rc;

	swc->is_internal_use = is_internal_use;
	rc = sepgsqlExprWalker(node, swc);
	swc->is_internal_use = saved_is_internal_use;

	return rc;
}

/* *******************************************************************************
 * proxyRteXXXX() -- check any relation type objects in the required query,
 * including general relation, outer|inner|cross join and subquery.
 * 
 * sepgsqlProxyQuery() is called just after query rewriting phase to constract
 * a list of SEvalItems. It is attached into Query->pgaceList and evaluated by
 * sepgsqlVerifyQuery() at later phase.
 * *******************************************************************************/

static void checkSelectFromExpr(sepgsqlWalkerContext *swc, Query *query, Node *node)
{
	if (node == NULL)
		return;

	switch (nodeTag(node))
	{
		case T_RangeTblRef: {
			RangeTblRef *rtr = (RangeTblRef *) node;
			RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

			if (rte->rtekind == RTE_RELATION)
				swc->selist = addEvalRelationRTE(swc->selist, rte, DB_TABLE__SELECT);
			break;
		}
		case T_JoinExpr: {
			JoinExpr *j = (JoinExpr *) node;

			checkSelectFromExpr(swc, query, j->larg);
			checkSelectFromExpr(swc, query, j->rarg);
			break;
		}
		case T_FromExpr: {
			FromExpr *f = (FromExpr *) node;
			ListCell *l;

			foreach (l, f->fromlist)
				checkSelectFromExpr(swc, query, lfirst(l));
			break;
		}
		default:
			elog(ERROR, "SELinux: unexpected node type (%d) on fromlist", nodeTag(node));
	}
}

static void proxyJoinTree(sepgsqlWalkerContext *swc, Node *node)
{
	Query *query = swc->qstack->query;

	if (node == NULL)
		return;

	switch (nodeTag(node))
	{
		case T_RangeTblRef: {
			RangeTblRef *rtr = (RangeTblRef *) node;
			RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);
			Assert(IsA(rte, RangeTblEntry));

			switch (rte->rtekind)
			{
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
			break;
		}
		case T_FromExpr: {
			FromExpr *f = (FromExpr *)node;
			ListCell *l;

			sepgsqlExprWalkerFlags(f->quals, swc, true);
			foreach (l, f->fromlist)
				proxyJoinTree(swc, lfirst(l));
			break;
		}
		case T_JoinExpr: {
			JoinExpr *j = (JoinExpr *) node;

			sepgsqlExprWalkerFlags(j->quals, swc, true);
			proxyJoinTree(swc, j->larg);
			proxyJoinTree(swc, j->rarg);

			break;
		}
		default:
			elog(ERROR, "SELinux: unexpected node type (%d) at jointree",
				 nodeTag(node));
			break;
	}
}

static void proxySetOperations(sepgsqlWalkerContext *swc, Node *node)
{
	Query *query = swc->qstack->query;

	if (node == NULL)
		return;

	switch (nodeTag(node))
	{
		case T_RangeTblRef: {
			RangeTblRef *rtr = (RangeTblRef *) node;
			RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

			Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_SUBQUERY);
			proxyRteSubQuery(swc, rte->subquery);

			break;
		}
		case T_SetOperationStmt: {
			SetOperationStmt *sop = (SetOperationStmt *) node;

			proxySetOperations(swc, sop->larg);
			proxySetOperations(swc, sop->rarg);
			break;
		}
		default:
			elog(ERROR, "SELinux enexpected node (%d) in setOperations tree",
				 nodeTag(node));
			break;
	}
}

static void proxyRteSubQuery(sepgsqlWalkerContext *swc, Query *query)
{
	CmdType cmdType = query->commandType;
	RangeTblEntry *rte = NULL;
	struct queryStack qsData;
	ListCell *l;

	/* push a query to queryStack */
	qsData.parent = swc->qstack;
	qsData.query = query;
	swc->qstack = &qsData;

	switch (cmdType) {
	case CMD_SELECT:
		checkSelectFromExpr(swc, query, (Node *) query->jointree);

	case CMD_UPDATE:
	case CMD_INSERT:
		foreach (l, query->targetList) {
			TargetEntry *tle = lfirst(l);
			bool is_security_attr = false;

			Assert(IsA(tle, TargetEntry));

			if (tle->resjunk && tle->resname
				&& !strcmp(tle->resname, SECURITY_SYSATTR_NAME))
				is_security_attr = true;

			/* pure junk target entries */
			if (tle->resjunk && !is_security_attr) {
				sepgsqlExprWalkerFlags((Node *) tle->expr, swc, true);
				continue;
			}

			sepgsqlExprWalkerFlags((Node *) tle->expr, swc, false);

			if (cmdType == CMD_SELECT)
				continue;

			rte = list_nth(query->rtable, query->resultRelation - 1);
			Assert(IsA(rte, RangeTblEntry) && rte->rtekind==RTE_RELATION);

			swc->selist = addEvalAttributeRTE(swc->selist, rte,
											  is_security_attr ? SecurityAttributeNumber : tle->resno,
											  cmdType == CMD_UPDATE ? DB_COLUMN__UPDATE : DB_COLUMN__INSERT);
		}
		break;

	case CMD_DELETE:
		rte = rt_fetch(query->resultRelation, query->rtable);
		Assert(IsA(rte, RangeTblEntry) && rte->rtekind==RTE_RELATION);
		swc->selist = addEvalRelationRTE(swc->selist, rte, DB_TABLE__DELETE);
		break;

	default:
		elog(ERROR, "SELinux: unexpected cmdType = %d", cmdType);
		break;
	}

	/* permission mark on RETURNING clause, if necessary */
	foreach (l, query->returningList) {
		TargetEntry *te = lfirst(l);
		Assert(IsA(te, TargetEntry));
		sepgsqlExprWalkerFlags((Node *) te->expr, swc, false);
	}

	/* permission mark on the WHERE/HAVING clause */
	sepgsqlExprWalkerFlags(query->jointree->quals, swc, true);
	sepgsqlExprWalkerFlags(query->havingQual, swc, true);

	/* permission mark on the ORDER BY clause */
	// MEMO: no need to walk it again, it is checked as junk entries
	//selist = sepgsqlWalkExpr(selist, qc, (Node *) query->sortClause, WKFLAG_INTERNAL_USE);

	/* permission mark on the GROUP BY/HAVING clause */
	// MEMO: no need to walk it again, it is checked as junk entries
	//selist = sepgsqlWalkExpr(selist, qc, (Node *) query->groupClause, WKFLAG_INTERNAL_USE);

	/* permission mark on the UNION/INTERSECT/EXCEPT */
	proxySetOperations(swc, query->setOperations);

	/* append sepgsql_permission() on the FROM clause/USING clause
	 * for SELECT/UPDATE/DELETE statement.
	 * The target Relation of INSERT is noe necessary to append it
	 */
	proxyJoinTree(swc, (Node *) query->jointree);

	/* pop a query to queryStack */
	swc->qstack = qsData.parent;
}

static List *proxyGeneralQuery(Query *query)
{
	sepgsqlWalkerContext swcData;
	memset(&swcData, 0, sizeof(sepgsqlWalkerContext));

	proxyRteSubQuery(&swcData, query);
	query->pgaceItem = (Node *) swcData.selist;

	return list_make1(query);
}

List *sepgsqlProxyQuery(Query *query)
{
	List *new_list = NIL;

	switch (query->commandType) {
	case CMD_SELECT:
	case CMD_UPDATE:
	case CMD_INSERT:
	case CMD_DELETE:
		new_list = proxyGeneralQuery(query);
		break;
	default:
		/* do nothing */
		new_list = list_make1(query);
		break;
	}
	return new_list;
}

void sepgsqlEvaluateParams(List *params)
{
	sepgsqlWalkerContext swcData;
	queryStack qsData;

	memset(&qsData, 0, sizeof(queryStack));
	memset(&swcData, 0, sizeof(sepgsqlWalkerContext));
	swcData.qstack = &qsData;

	sepgsqlExprWalkerFlags((Node *)params, &swcData, false);

	execVerifyQuery(swcData.selist);
}

/* *******************************************************************************
 * verifyXXXX() -- checks any SEvalItem attached with Query->pgaceList.
 * Those are generated in proxyXXXX() phase, and this evaluation is done
 * just before PortalStart().
 * The reason why the checks are delayed is to handle cases when parse
 * and execute are separated like PREPARE/EXECUTE statement.
 * *******************************************************************************/
static void verifyPgClassPerms(Oid relid, bool inh, uint32 perms)
{
	HeapTuple tuple;

	/* prevent to modify pg_security directly */
	if (relid == SecurityRelationId
		&& (perms & (DB_TABLE__UPDATE | DB_TABLE__INSERT | DB_TABLE__DELETE)) != 0)
		elog(ERROR, "SELinux: user cannot modify pg_security directly");

	/* check table:{required permissions} */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: relation (oid=%u) does not exist", relid);
	if (((Form_pg_class) GETSTRUCT(tuple))->relkind == RELKIND_RELATION)
	{
		security_context_t tcontext;
		char nmbuf[256];
		bool has_name;

		tcontext = pgaceSidToSecurityLabel(HeapTupleGetSecurity(tuple));
		has_name = sepgsqlGetTupleName(RelationRelationId, tuple, nmbuf, sizeof(nmbuf));

		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 tcontext,
							 SECCLASS_DB_TABLE,
							 (access_vector_t) perms,
							 has_name ? nmbuf : NULL);
	}
	ReleaseSysCache(tuple);
}

static void verifyPgAttributePerms(Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	HeapTuple tuple;
	security_context_t tcontext;
	char nmbuf[256];
	bool has_name;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: relation (oid=%u) does not exist", relid);
	if (((Form_pg_class) GETSTRUCT(tuple))->relkind != RELKIND_RELATION)
	{
		ReleaseSysCache(tuple);
		return;
	}
	ReleaseSysCache(tuple);

	/* 2. verify column perms */
	if (attno == 0) {
		/* RECORD type permission check */
		Relation rel;
		ScanKeyData skey;
		SysScanDesc scan;

		ScanKeyInit(&skey,
					Anum_pg_attribute_attrelid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(relid));

		rel = heap_open(AttributeRelationId, AccessShareLock);
		scan = systable_beginscan(rel, AttributeRelidNumIndexId,
								  true, SnapshotNow, 1, &skey);
		while ((tuple = systable_getnext(scan)) != NULL) {
			Form_pg_attribute attForm
				= (Form_pg_attribute) GETSTRUCT(tuple);

			if (attForm->attisdropped || attForm->attnum < 1)
				continue;

			tcontext = pgaceSidToSecurityLabel(HeapTupleGetSecurity(tuple));
			has_name = sepgsqlGetTupleName(AttributeRelationId, tuple, nmbuf, sizeof(nmbuf));
			sepgsqlAvcPermission(sepgsqlGetClientContext(),
								 tcontext,
								 SECCLASS_DB_COLUMN,
								 perms,
								 has_name ? nmbuf : NULL);
			pfree(tcontext);
		}
		systable_endscan(scan);
		heap_close(rel, AccessShareLock);

		return;
	}
	/* check required column's permission */
	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %u", attno, relid);

	tcontext = pgaceSidToSecurityLabel(HeapTupleGetSecurity(tuple));
	has_name = sepgsqlGetTupleName(AttributeRelationId, tuple, nmbuf, sizeof(nmbuf));
	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 tcontext,
						 SECCLASS_DB_COLUMN,
						 perms,
						 has_name ? nmbuf : NULL);
	pfree(tcontext);
	ReleaseSysCache(tuple);
}

static void verifyPgProcPerms(Oid funcid, uint32 perms)
{
	HeapTuple tuple;
	security_context_t tcontext, ncontext;
	char nmbuf[256];
	bool has_name;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(funcid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure %d", funcid);
	tcontext = pgaceSidToSecurityLabel(HeapTupleGetSecurity(tuple));
	has_name = sepgsqlGetTupleName(ProcedureRelationId, tuple, nmbuf, sizeof(nmbuf));

	/* check domain transition */
	ncontext = sepgsqlAvcCreateCon(sepgsqlGetClientContext(),
								   tcontext,
								   SECCLASS_PROCESS);
	if (strcmp(sepgsqlGetClientContext(), ncontext))
	{
		perms |= DB_PROCEDURE__ENTRYPOINT;

		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 ncontext,
							 SECCLASS_PROCESS,
							 PROCESS__TRANSITION,
							 NULL);
	}
	pfree(ncontext);

	/* check procedure executiong permission */
	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 tcontext,
						 SECCLASS_DB_PROCEDURE,
						 perms,
						 has_name ? nmbuf : NULL);
	pfree(tcontext);

	ReleaseSysCache(tuple);
}

static List *expandRelationInheritance(List *selist, Oid relid, uint32 perms)
{
	List *inherits = find_all_inheritors(relid);
	ListCell *l;

	foreach (l, inherits)
		selist = addEvalRelation(selist, lfirst_oid(l), false, perms);

	return selist;
}

static List *expandAttributeInheritance(List *selist, Oid relid, char *attname, uint32 perms)
{
	List *inherits = find_all_inheritors(relid);
	ListCell *l;

	foreach (l, inherits)
	{
		Form_pg_attribute attr;
		HeapTuple tuple;

		if (!attname)
		{
			selist = addEvalAttribute(selist, lfirst_oid(l), false, 0, perms);
			continue;
		}

		tuple = SearchSysCacheAttName(lfirst_oid(l), attname);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for attribute %s of relation %u",
				 attname, lfirst_oid(l));

		attr = (Form_pg_attribute) GETSTRUCT(tuple);
		selist = addEvalAttribute(selist, lfirst_oid(l), false, attr->attnum, perms);

		ReleaseSysCache(tuple);
	}

	return selist;
}

static List *expandSEvalItemInheritance(List *selist)
{
	SEvalItemRelation *ser;
	SEvalItemAttribute *sea;

	List *result = NIL;
	ListCell *l;

	foreach (l, selist)
	{
		Node *node = lfirst(l);

		result = lappend(result, node);
		switch (nodeTag(node))
		{
		case T_SEvalItemRelation:
			ser = (SEvalItemRelation *) node;
			if (ser->inh) {
				ser->inh = false;
				result = expandRelationInheritance(result,
												   ser->relid,
												   ser->perms);
			}
			break;

		case T_SEvalItemAttribute:
			sea = (SEvalItemAttribute *) node;
			if (sea->inh) {
				Form_pg_attribute attr;
				HeapTuple tuple;

				sea->inh = false;
				if (sea->attno == 0)
				{
					result = expandAttributeInheritance(result,
														sea->relid,
														NULL,
														sea->perms);
					break;
				}

				tuple = SearchSysCache(ATTNUM,
									   ObjectIdGetDatum(sea->relid),
									   Int16GetDatum(sea->attno),
									   0, 0);
				if (!HeapTupleIsValid(tuple))
					elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %u",
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
			/* do nothing */
			break;

		default:
			elog(ERROR, "Invalid node type (%d) in SEvalItemList", nodeTag(node));
			break;
		}
	}
	return result;
}

static void execVerifyQuery(List *selist)
{
	SEvalItemRelation *ser;
	SEvalItemAttribute *sea;
	SEvalItemProcedure *sep;
	ListCell *l;

	foreach (l, selist)
	{
		Node *node = lfirst(l);

		switch  (nodeTag(node))
		{
		case T_SEvalItemRelation:
			ser = (SEvalItemRelation *) node;
			verifyPgClassPerms(ser->relid, ser->inh, ser->perms);
			break;

		case T_SEvalItemAttribute:
			sea = (SEvalItemAttribute *) node;
			verifyPgAttributePerms(sea->relid, sea->inh, sea->attno, sea->perms);
			break;

		case T_SEvalItemProcedure:
			sep = (SEvalItemProcedure *) node;
			verifyPgProcPerms(sep->funcid, sep->perms);
			break;

		default:
			elog(ERROR, "Invalid node type (%d) in SEvalItemList", nodeTag(node));
			break;
		}
	}

}

void sepgsqlVerifyQuery(PlannedStmt *pstmt, int eflags)
{
	RangeTblEntry *rte;
	List *selist;
	ListCell *l;

	/* EXPLAIN statement does not access any object. */
	if (eflags & EXEC_FLAG_EXPLAIN_ONLY)
		return;
	if (!pstmt->pgaceItem)
		return;

	Assert(IsA(pstmt->pgaceItem, List));
	selist = copyObject(pstmt->pgaceItem);

	/* expand table inheritances */
	selist = expandSEvalItemInheritance(selist);

	/* add checks for access via trigger function */
	foreach(l, pstmt->resultRelations) {
		Index rindex = lfirst_int(l);

		rte = rt_fetch(rindex, pstmt->rtable);
		Assert(IsA(rte, RangeTblEntry));

		selist = addEvalTriggerAccess(selist, rte->relid, rte->inh, pstmt->commandType);
	}
	execVerifyQuery(selist);
}

/* --------------------------------------------------------------
 * Process Utility hooks
 * --------------------------------------------------------------
 */

static void checkTruncateStmt(TruncateStmt *stmt)
{
	Relation rel;
	HeapScanDesc scan;
	HeapTuple tuple;
	List *relidList = NIL;
	ListCell *l;

	foreach (l, stmt->relations) {
		RangeVar *rv = lfirst(l);

		relidList = lappend_oid(relidList,
								RangeVarGetRelid(rv, false));
	}

	if (stmt->behavior == DROP_CASCADE) {
		relidList = list_concat(relidList,
								heap_truncate_find_FKs(relidList));
	}

	foreach (l, relidList) {
		Oid relid = lfirst_oid(l);
		security_context_t tcontext;
		char nmbuf[256];
		bool has_name;

		/* 1. db_table:{delete} */
		tuple = SearchSysCache(RELOID,
							   ObjectIdGetDatum(relid), 0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);
		tcontext = pgaceSidToSecurityLabel(HeapTupleGetSecurity(tuple));
		has_name = sepgsqlGetTupleName(RelationRelationId, tuple, nmbuf, sizeof(nmbuf));
		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 tcontext,
							 SECCLASS_DB_TABLE,
							 DB_TABLE__DELETE,
							 has_name ? nmbuf : NULL);
		pfree(tcontext);
		ReleaseSysCache(tuple);

		/* 2. db_tuple:{delete} */
		rel = heap_open(relid, AccessShareLock);
		scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			tcontext = pgaceSidToSecurityLabel(HeapTupleGetSecurity(tuple));
			has_name = sepgsqlGetTupleName(RelationRelationId, tuple, nmbuf, sizeof(nmbuf));
			sepgsqlAvcPermission(sepgsqlGetClientContext(),
								 tcontext,
								 SECCLASS_DB_TUPLE,
								 DB_TUPLE__DELETE,
								 has_name ? nmbuf : NULL);
			pfree(tcontext);
		}
		heap_endscan(scan);
		heap_close(rel, AccessShareLock);
	}
}

void sepgsqlProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel)
{
	switch (nodeTag(parsetree))
	{
	case T_TruncateStmt:
		checkTruncateStmt((TruncateStmt *) parsetree);
		break;
	default:
		/* do nothing  */
		break;
	}
}

/* *******************************************************************************
 * PGACE hooks: we cannon the following hooks in sepgsqlHooks.c because they
 * refers static defined variables in sepgsqlProxy.c
 * *******************************************************************************/

/* ----------------------------------------------------------
 * COPY TO/COPY FROM statement hooks
 * ---------------------------------------------------------- */
void sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom)
{
	List *selist = NIL;
	ListCell *l;

	/* on 'COPY FROM SELECT ...' cases, any checkings are done in select.c */
	if (rel == NULL)
		return;

	/* no need to check non-table relation */
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return;

	selist = addEvalRelation(selist, RelationGetRelid(rel), false,
							 isFrom ? DB_TABLE__INSERT : DB_TABLE__SELECT);
	foreach (l, attNumList) {
		AttrNumber attnum = lfirst_int(l);

		selist = addEvalAttribute(selist, RelationGetRelid(rel), false, attnum,
								  isFrom ? DB_COLUMN__INSERT : DB_COLUMN__SELECT);
	}

	/* check call trigger function */
	if (isFrom)
		selist = addEvalTriggerAccess(selist, RelationGetRelid(rel), false, CMD_INSERT);

	execVerifyQuery(selist);
}

bool sepgsqlCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	uint32 perms = SEPGSQL_PERMS_SELECT;

	/* for 'pg_largeobject' */
	if (RelationGetRelid(rel) == LargeObjectRelationId) {
		ListCell *l;

		foreach (l, attNumList) {
			AttrNumber attnum = lfirst_int(l);
			if (attnum == Anum_pg_largeobject_data) {
				perms |= SEPGSQL_PERMS_READ;
				break;
			}
		}
	}
	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms, false);
}

