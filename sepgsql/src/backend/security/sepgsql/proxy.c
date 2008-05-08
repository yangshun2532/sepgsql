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
#include "optimizer/clauses.h"
#include "optimizer/plancat.h"
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
static void proxyRteRelation(sepgsqlWalkerContext *swc, int rtindex, Node **quals);
static void proxyRteSubQuery(sepgsqlWalkerContext *swc, Query *query);
static void proxyJoinTree(sepgsqlWalkerContext *swc, Node *node, Node **quals);
static void proxySetOperations(sepgsqlWalkerContext *swc, Node *node);

/* static  */
static bool sepgsqlExprWalker(Node *node, sepgsqlWalkerContext *swc);

/* -----------------------------------------------------------
 * addEvalXXXX -- add evaluation items into Query->SEvalItemList.
 * Those are used for execution phase.
 * ----------------------------------------------------------- */
static List *__addEvalPgClass(List *selist, Oid relid, bool inh, uint32 perms)
{
	SEvalItem *se;
	ListCell *l;

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_DB_TABLE
			&& se->c.relid == relid
			&& se->c.inh == inh) {
			se->perms |= perms;
			return selist;
		}
	}
	/* not found */
	se = makeNode(SEvalItem);
	se->tclass = SECCLASS_DB_TABLE;
	se->perms = perms;
	se->c.relid = relid;
	se->c.inh = inh;

	return lappend(selist, se);
}

static List *addEvalPgClass(List *selist, RangeTblEntry *rte, uint32 perms)
{
	rte->requiredPerms |= (perms & DB_TABLE__USE    ? SEPGSQL_PERMS_USE : 0);
	rte->requiredPerms |= (perms & DB_TABLE__SELECT ? SEPGSQL_PERMS_SELECT : 0);
	rte->requiredPerms |= (perms & DB_TABLE__INSERT ? SEPGSQL_PERMS_INSERT : 0);
	rte->requiredPerms |= (perms & DB_TABLE__UPDATE ? SEPGSQL_PERMS_UPDATE : 0);
	rte->requiredPerms |= (perms & DB_TABLE__DELETE ? SEPGSQL_PERMS_DELETE : 0);

	/* for 'pg_largeobject' */
	if (rte->relid == LargeObjectRelationId && (perms & DB_TABLE__DELETE))
		rte->requiredPerms |= SEPGSQL_PERMS_WRITE;

	return __addEvalPgClass(selist, rte->relid, rte->inh, perms);
}

static List *__addEvalPgAttribute(List *selist, Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	ListCell *l;
	SEvalItem *se;

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_DB_COLUMN
			&& se->a.relid == relid
			&& se->a.inh == inh
			&& se->a.attno == attno) {
			se->perms |= perms;
			return selist;
		}
	}
	/* not found */
	se = makeNode(SEvalItem);
	se->tclass = SECCLASS_DB_COLUMN;
	se->perms = perms;
	se->a.relid = relid;
	se->a.inh = inh;
	se->a.attno = attno;

	return lappend(selist, se);
}

static List *addEvalPgAttribute(List *selist, RangeTblEntry *rte, AttrNumber attno, uint32 perms)
{
	uint32 t_perms = 0;

	/* for table:{ ... } permission */
	t_perms |= (perms & DB_COLUMN__USE    ? DB_TABLE__USE : 0);
	t_perms |= (perms & DB_COLUMN__SELECT ? DB_TABLE__SELECT : 0);
	t_perms |= (perms & DB_COLUMN__INSERT ? DB_TABLE__INSERT : 0);
	t_perms |= (perms & DB_COLUMN__UPDATE ? DB_TABLE__UPDATE : 0);
	selist = addEvalPgClass(selist, rte, t_perms);

	/* for 'security_context' */
	if (attno == SecurityAttributeNumber
		&& (perms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT)))
		rte->requiredPerms |= SEPGSQL_PERMS_RELABELFROM;

	/* for 'pg_largeobject' */
	if (rte->relid == LargeObjectRelationId) {
		if ((perms & DB_COLUMN__SELECT) && attno == Anum_pg_largeobject_data)
			rte->requiredPerms |= SEPGSQL_PERMS_READ;
		if ((perms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT)) && attno > 0)
			rte->requiredPerms |= SEPGSQL_PERMS_WRITE;
	}

	return __addEvalPgAttribute(selist, rte->relid, rte->inh, attno, perms);
}

static List *addEvalPgProc(List *selist, Oid funcid, uint32 perms)
{
	ListCell *l;
	SEvalItem *se;

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_DB_PROCEDURE
			&& se->p.funcid == funcid) {
			se->perms |= perms;
			return selist;
		}
	}
	se = makeNode(SEvalItem);
	se->tclass = SECCLASS_DB_PROCEDURE;
	se->perms = perms;
	se->p.funcid = funcid;

	return lappend(selist, se);
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

			selist = __addEvalPgClass(selist, relid, false, DB_TABLE__SELECT);
			for (attnum = FirstLowInvalidHeapAttributeNumber + 1; attnum <= 0; attnum++) {
				if (attnum == ObjectIdAttributeNumber && !classForm->relhasoids)
					continue;
				selist = __addEvalPgAttribute(selist, relid, false, attnum, DB_COLUMN__SELECT);
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
	Node *node;
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
	rte = rt_fetch(var->varno, query->rtable);
	Assert(IsA(rte, RangeTblEntry));

	switch (rte->rtekind) {
	case RTE_RELATION:
		/* table:{select/use} and column:{select/use} */
		swc->selist = addEvalPgAttribute(swc->selist, rte, var->varattno,
										 swc->is_internal_use
										 ? DB_COLUMN__USE : DB_COLUMN__SELECT);
		break;

	case RTE_JOIN:
		node = list_nth(rte->joinaliasvars, var->varattno - 1);
		sepgsqlExprWalker(node, swc);
		break;

	case RTE_SUBQUERY:
		/* In normal cases, rte->relid equals zero for subquery.
		 * If rte->relid has none-zero value, it's rewritten subquery
		 * for outer join handling.
		 */
		if (rte->relid) {
			Query *sqry = rte->subquery;
			RangeTblEntry *srte;
			TargetEntry *tle;
			Var *svar;

			Assert(sqry->commandType == CMD_SELECT);
			Assert(list_length(sqry->rtable) == 1);

			srte = (RangeTblEntry *) list_nth(sqry->rtable, 0);
			Assert(srte->rtekind == RTE_RELATION);
			Assert(srte->relid == rte->relid);

			if (var->varattno < 1) {
				ListCell *l;
				bool found = false;

				foreach(l, sqry->targetList) {
					TargetEntry *tle = lfirst(l);

					Assert(IsA(tle, TargetEntry));
					if (IsA(tle->expr, Const))
						continue;

					svar = (Var *) tle->expr;
					Assert(IsA(svar, Var));
					if (svar->varattno == var->varattno) {
						var->varattno = tle->resno;
						found = true;
						break;
					}
				}
				if (!found) {
					AttrNumber resno = list_length(sqry->targetList) + 1;
					svar = makeVar(1,
								   var->varattno,
								   var->vartype,
								   var->vartypmod,
								   0);
					tle = makeTargetEntry((Expr *) svar, resno, NULL, false);
					var->varattno = resno;
					sqry->targetList = lappend(sqry->targetList, tle);
				}
			} else {
				tle = list_nth(sqry->targetList, var->varattno - 1);
				Assert(IsA(tle, TargetEntry));
				if (!IsA(tle->expr, Var))
					elog(ERROR, "SELinux: refering to dropped column (relid=%u, attno=%d)",
						 rte->relid, var->varattno);
				svar = (Var *) tle->expr;
			}
			/* table:{select/use} and column:{select/use} */
			swc->selist = addEvalPgAttribute(swc->selist, srte, svar->varattno,
											 swc->is_internal_use
											 ? DB_COLUMN__USE : DB_COLUMN__SELECT);
		}
		break;

	case RTE_SPECIAL:
	case RTE_FUNCTION:
	case RTE_VALUES:
		/* do nothing */
		break;

	default:
		elog(ERROR, "SELinux: unexpected rtekind (%d)", rte->rtekind);
		break;
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
		swc->selist = addEvalPgProc(swc->selist, ((FuncExpr *) node)->funcid, DB_PROCEDURE__EXECUTE);
		break;

	case T_Aggref:
		swc->selist = addEvalPgProc(swc->selist, ((Aggref *) node)->aggfnoid, DB_PROCEDURE__EXECUTE);
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
			swc->selist = addEvalPgProc(swc->selist, ace->elemfuncid, DB_PROCEDURE__EXECUTE);
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

static Oid fnoid_sepgsql_tuple_perm = F_SEPGSQL_TUPLE_PERMS;

/*
 * When we use LEFT OUTER JOIN, any condition defined at ON clause are not
 * considered to filter tuples, so left-hand relation have to be re-written
 * as a subquery to filter violated tuples.
 */
static List *makePseudoTargetList(Oid relid) {
	HeapTuple reltup, atttup;
	Form_pg_class classForm;
	Form_pg_attribute attrForm;
	AttrNumber attno, relnatts;
	TargetEntry *tle;
	Expr *expr;
	List *targetList = NIL;

	reltup = SearchSysCache(RELOID,
							ObjectIdGetDatum(relid),
							0, 0, 0);
	if (!HeapTupleIsValid(reltup))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	classForm = (Form_pg_class) GETSTRUCT(reltup);
	relnatts = classForm->relnatts;
	for (attno = 1; attno <= relnatts; attno++) {
		atttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(relid),
								Int16GetDatum(attno),
								0, 0);
		if (!HeapTupleIsValid(atttup))
			elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %s",
				 attno, NameStr(classForm->relname));
		attrForm = (Form_pg_attribute) GETSTRUCT(atttup);
		if (attrForm->attisdropped) {
			expr = (Expr *) makeNullConst(INT4OID, -1);
		} else {
			expr = (Expr *) makeVar(1,
									attno,
									attrForm->atttypid,
									attrForm->atttypmod,
									0);
		}
		tle = makeTargetEntry(expr, attno, NULL, false);
		targetList = lappend(targetList, tle);
		ReleaseSysCache(atttup);

		Assert(list_length(targetList) == attno);
	}
	ReleaseSysCache(reltup);

	return targetList;
}

static void rewriteOuterJoinTree(Node *n, Query *query, bool is_outer_join)
{
	RangeTblRef *rtr, *srtr;
	RangeTblEntry *rte, *srte;
	Query *sqry;
	FromExpr *sfrm;

	if (IsA(n, RangeTblRef)) {
		if (!is_outer_join)
			return;

		rtr = (RangeTblRef *) n;
		rte = list_nth(query->rtable, rtr->rtindex - 1);
		Assert(IsA(rte, RangeTblEntry));
		if (rte->rtekind != RTE_RELATION)
			return;

		/* setup alternative query */
		sqry = makeNode(Query);
		sqry->commandType = CMD_SELECT;
		sqry->targetList = makePseudoTargetList(rte->relid);

		srte = copyObject(rte);
		sqry->rtable = list_make1(srte);

		srtr = makeNode(RangeTblRef);
		srtr->rtindex = 1;

		sfrm = makeNode(FromExpr);
		sfrm->fromlist = list_make1(srtr);
		sfrm->quals = NULL;

		sqry->jointree = sfrm;
        sqry->hasSubLinks = false;
        sqry->hasAggs = false;

		rte->rtekind = RTE_SUBQUERY;
		rte->subquery = sqry;
	} else if (IsA(n, FromExpr)) {
		FromExpr *f = (FromExpr *)n;
        ListCell *l;

        foreach (l, f->fromlist)
			rewriteOuterJoinTree(lfirst(l), query, false);
	} else if (IsA(n, JoinExpr)) {
        JoinExpr *j = (JoinExpr *) n;

		rewriteOuterJoinTree(j->larg, query,
							 (j->jointype == JOIN_LEFT || j->jointype == JOIN_FULL));
		rewriteOuterJoinTree(j->rarg, query,
							 (j->jointype == JOIN_RIGHT || j->jointype == JOIN_FULL));
	} else {
		elog(ERROR, "SELinux: unexpected node type (%d) in Query->jointree", nodeTag(n));
	}
}

static void proxyRteRelation(sepgsqlWalkerContext *swc, int rtindex, Node **quals)
{
	Query *query = swc->qstack->query;
	RangeTblEntry *rte;
	Relation rel;
	TupleDesc tdesc;
	uint32 perms;

	rte = rt_fetch(rtindex, query->rtable);
	rel = relation_open(rte->relid, AccessShareLock);
	tdesc = RelationGetDescr(rel);

	/* setup tclass and access vector */
	perms = rte->requiredPerms & SEPGSQL_PERMS_ALL;

	/* append sepgsql_tuple_perm(relid, record, perms) */
	if (perms) {
		Var *v1, *v2, *v4;
		Const *c3;
		FuncExpr *func;

		/* 1st arg : Oid of the target relation */
		v1 = makeVar(rtindex, TableOidAttributeNumber, OIDOID, -1, 0);

		/* 2nd arg : Security Attribute of tuple */
		v2 = makeVar(rtindex, SecurityAttributeNumber, OIDOID, -1, 0);
		
		/* 3rd arg : permission set */
		c3 = makeConst(INT4OID, -1, sizeof(int32), Int32GetDatum(perms), false, true);

		/* 4th arg : RECORD of the target relation */
		v4 = makeVar(rtindex, 0, RelationGetForm(rel)->reltype, -1, 0);

		/* append sepgsql_tuple_perm */
		func = makeFuncExpr(fnoid_sepgsql_tuple_perm, BOOLOID,
							list_make4(v1, v2, c3, v4), COERCE_DONTCARE);
		if (*quals == NULL) {
			*quals = (Node *) func;
		} else {
			*quals = (Node *) makeBoolExpr(AND_EXPR, list_make2(func, *quals));
		}
	}
	relation_close(rel, AccessShareLock);
}

static void proxyRteOuterJoin(sepgsqlWalkerContext *swc, Query *query)
{
	struct queryStack qsData;
	ListCell *l;

	qsData.parent = swc->qstack;
	qsData.query = query;
	swc->qstack = &qsData;

	proxyRteRelation(swc, 1, &query->jointree->quals);

	/* clean-up polluted RangeTblEntry */
	foreach (l, query->rtable) {
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(l);
		rte->requiredPerms &= ~SEPGSQL_PERMS_ALL;
	}
	swc->qstack = qsData.parent;
}

static void __checkSelectTargets(sepgsqlWalkerContext *swc, Query *query, Node *node)
{
	if (node == NULL)
		return;

	if (IsA(node, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

		switch (rte->rtekind) {
		case RTE_RELATION:
			swc->selist = addEvalPgClass(swc->selist, rte, DB_TABLE__SELECT);
			break;
		case RTE_SUBQUERY:
			if (rte->relid) {
				Query *sqry = rte->subquery;
				RangeTblEntry *srte = rt_fetch(1, sqry->rtable);

				swc->selist = addEvalPgClass(swc->selist, srte, DB_TABLE__SELECT);
			}
			break;
		default:
			/* do nothing */
			break;
		}
	} else if (IsA(node, JoinExpr)) {
		__checkSelectTargets(swc, query, ((JoinExpr *) node)->larg);
		__checkSelectTargets(swc, query, ((JoinExpr *) node)->rarg);

	} else if (IsA(node, FromExpr)) {
		ListCell *l;

		foreach (l, ((FromExpr *)node)->fromlist)
			__checkSelectTargets(swc, query, lfirst(l));
	} else {
		elog(ERROR, "SELinux: unexpected node type (%d) at Query->fromlist", nodeTag(node));
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

	/* rewrite outer join */
	rewriteOuterJoinTree((Node *) query->jointree, query, false);

	switch (cmdType) {
	case CMD_SELECT:
		__checkSelectTargets(swc, query, (Node *)query->jointree);

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

			swc->selist = addEvalPgAttribute(swc->selist, rte,
											 is_security_attr ? SecurityAttributeNumber : tle->resno,
											 cmdType == CMD_UPDATE ? DB_COLUMN__UPDATE : DB_COLUMN__INSERT);
		}
		break;

	case CMD_DELETE:
		rte = rt_fetch(query->resultRelation, query->rtable);
		Assert(IsA(rte, RangeTblEntry) && rte->rtekind==RTE_RELATION);
		swc->selist = addEvalPgClass(swc->selist, rte, DB_TABLE__DELETE);
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
	proxyJoinTree(swc, (Node *) query->jointree, &query->jointree->quals);

	/* clean-up polluted RangeTblEntry */
	foreach (l, query->rtable) {
		rte = (RangeTblEntry *) lfirst(l);
		rte->requiredPerms &= ~SEPGSQL_PERMS_ALL;
	}

	/* pop a query to queryStack */
	swc->qstack = qsData.parent;
}

static void proxyJoinTree(sepgsqlWalkerContext *swc, Node *node, Node **quals)
{
	Query *query = swc->qstack->query;

	if (node == NULL)
		return;

	if (IsA(node, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);
		Assert(IsA(rte, RangeTblEntry));

		switch (rte->rtekind) {
		case RTE_RELATION:
			proxyRteRelation(swc, rtr->rtindex, quals);
			break;

		case RTE_SUBQUERY:
			if (rte->relid) {
				proxyRteOuterJoin(swc, rte->subquery);
			} else {
				proxyRteSubQuery(swc, rte->subquery);
			}
			break;

		case RTE_FUNCTION:
			sepgsqlExprWalkerFlags(rte->funcexpr, swc, false);
			break;

		case RTE_VALUES:
			sepgsqlExprWalkerFlags((Node *) rte->values_lists, swc, false);
			break;

		default:
			elog(ERROR, "SELinux: unexpected rtekinf = %d at fromList", rte->rtekind);
			break;
		}
	} else if (IsA(node, FromExpr)) {
		FromExpr *f = (FromExpr *)node;
		ListCell *l;

		sepgsqlExprWalkerFlags(f->quals, swc, true);
		foreach (l, f->fromlist)
			proxyJoinTree(swc, lfirst(l), quals);
	} else if (IsA(node, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) node;

		sepgsqlExprWalkerFlags(j->quals, swc, true);
		proxyJoinTree(swc, j->larg, &j->quals);
		proxyJoinTree(swc, j->rarg, &j->quals);
	} else {
		elog(ERROR, "SELinux: unexpected node type (%d) at Query->jointree", nodeTag(node));
	}
}

static void proxySetOperations(sepgsqlWalkerContext *swc, Node *node)
{
	Query *query = swc->qstack->query;

	if (node == NULL)
		return;

	if (IsA(node, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = rt_fetch(rtr->rtindex, query->rtable);

		Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_SUBQUERY);
		proxyRteSubQuery(swc, rte->subquery);

    } else if (IsA(node, SetOperationStmt)) {
		proxySetOperations(swc, ((SetOperationStmt *) node)->larg);
		proxySetOperations(swc, ((SetOperationStmt *) node)->rarg);

    } else {
		elog(ERROR, "SELinux: setOperationsTree contains => %s", nodeToString(node));
    }
}

static List *proxyGeneralQuery(Query *query)
{
	sepgsqlWalkerContext swcData;
	memset(&swcData, 0, sizeof(sepgsqlWalkerContext));

	proxyRteSubQuery(&swcData, query);
	query->pgaceItem = (Node *) swcData.selist;

	return list_make1(query);
}

static List *proxyExecuteStmt(Query *query)
{
	ExecuteStmt *estmt = (ExecuteStmt *) query->utilityStmt;
	sepgsqlWalkerContext swcData;
	queryStack qsData;

	Assert(nodeTag(query->utilityStmt) == T_ExecuteStmt);

	qsData.parent = NULL;
	qsData.query = query;
	memset(&swcData, 0, sizeof(sepgsqlWalkerContext));
	swcData.qstack = &qsData;

	sepgsqlExprWalkerFlags((Node *) estmt->params, &swcData, false);
	query->pgaceItem = (Node *) swcData.selist;

	return list_make1(query);
}

static List *convertTruncateToDelete(Relation rel)
{
	Query *query = makeNode(Query);
	RangeTblEntry *rte;
	RangeTblRef *rtr;

	rte = addRangeTableEntryForRelation(NULL, rel, NULL, false, false);
	rte->requiredPerms = ACL_DELETE;
	rtr = makeNode(RangeTblRef);
	rtr->rtindex = 1;

	query->commandType = CMD_DELETE;
	query->rtable = list_make1(rte);
	query->jointree = makeNode(FromExpr);
	query->jointree->fromlist = list_make1(rtr);
	query->jointree->quals = NULL;
	query->resultRelation = rtr->rtindex;
	query->hasSubLinks = false;
	query->hasAggs = false;

	return sepgsqlProxyQuery(query);
}

static List *proxyTruncateStmt(Query *query)
{
	TruncateStmt *stmt = (TruncateStmt *) query->utilityStmt;
	Relation rel;
	ListCell *l;
	List *subquery_list = NIL, *subquery_lids = NIL;

	/* resolve the relation names */
	foreach (l, stmt->relations) {
		RangeVar *rv = lfirst(l);

		rel = heap_openrv(rv, AccessShareLock);
		subquery_list = list_concat(subquery_list,
									convertTruncateToDelete(rel));
		subquery_lids = lappend_oid(subquery_lids,
									RelationGetRelid(rel));
		heap_close(rel, AccessShareLock);

		elog(NOTICE, "SELinux: TRUNCATE %s is replaced unconditional DELETE",
			 RelationGetRelationName(rel));
	}

	if (stmt->behavior == DROP_CASCADE) {
		subquery_lids = heap_truncate_find_FKs(subquery_lids);
		foreach (l, subquery_lids) {
			Oid relid = lfirst_oid(l);

			rel = heap_open(relid, AccessShareLock);
			subquery_list = lappend(subquery_list,
									convertTruncateToDelete(rel));
			heap_close(rel, AccessShareLock);
		}
	}
	return subquery_list;
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
	case CMD_UTILITY:
		switch (nodeTag(query->utilityStmt)) {
		case T_TruncateStmt:
			new_list = proxyTruncateStmt(query);
			break;
		case T_ExecuteStmt:
			new_list = proxyExecuteStmt(query);
			break;
		default:
			new_list = list_make1(query);
			/* do nothing now */
			break;
		}
		break;
	default:
		elog(ERROR, "SELinux: unexpected command type (%d)", query->commandType);
		break;
	}
	return new_list;
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
	Form_pg_class pgclass;
	HeapTuple tuple;
	NameData name;

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
	pgclass = (Form_pg_class) GETSTRUCT(tuple);

	if (pgclass->relkind != RELKIND_RELATION) {
		ReleaseSysCache(tuple);
		return;
	}

	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_TABLE,
						   perms,
						   sepgsqlGetTupleName(RelationRelationId, tuple, &name));
	ReleaseSysCache(tuple);
}

static void verifyPgAttributePerms(Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	HeapTuple tuple;
	Form_pg_class classForm;
	Form_pg_attribute attrForm;
	NameData name;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: relation (oid=%u) does not exist", relid);
	classForm = (Form_pg_class) GETSTRUCT(tuple);
	if (classForm->relkind != RELKIND_RELATION) {
		/* column:{ xxx } checks are applied only column within tables */
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
			attrForm = (Form_pg_attribute) GETSTRUCT(tuple);
			if (attrForm->attisdropped || attrForm->attnum < 1)
				continue;
			sepgsql_avc_permission(sepgsqlGetClientContext(),
								   HeapTupleGetSecurity(tuple),
								   SECCLASS_DB_COLUMN,
								   perms,
								   sepgsqlGetTupleName(AttributeRelationId, tuple, &name));
		}
		systable_endscan(scan);
		heap_close(rel, AccessShareLock);

		return;
	}

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %u", attno, relid);

	/* check column:{required permissions} */
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_COLUMN,
						   perms,
						   sepgsqlGetTupleName(AttributeRelationId, tuple, &name));
	ReleaseSysCache(tuple);
}

static void verifyPgProcPerms(Oid funcid, uint32 perms)
{
	HeapTuple tuple;
	NameData name;
	Oid newcon;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(funcid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure %d", funcid);

	/* compute domain transition */
	newcon = sepgsql_avc_createcon(sepgsqlGetClientContext(),
								   HeapTupleGetSecurity(tuple),
								   SECCLASS_PROCESS);
	if (newcon != sepgsqlGetClientContext())
		perms |= DB_PROCEDURE__ENTRYPOINT;

	/* check procedure executiong permission */
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_PROCEDURE,
						   perms,
						   sepgsqlGetTupleName(ProcedureRelationId, tuple, &name));

	/* check domain transition, if necessary */
	if (newcon != sepgsqlGetClientContext()) {
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   newcon,
							   SECCLASS_PROCESS,
							   PROCESS__TRANSITION,
							   NULL);
	}

	ReleaseSysCache(tuple);
}

static List *__expandPgClassInheritance(List *selist, Oid relid, uint32 perms)
{
	List *child_list = find_inheritance_children(relid);
	ListCell *l;

	foreach (l, child_list) {
		selist = __addEvalPgClass(selist, lfirst_oid(l), false, perms);
		selist = __expandPgClassInheritance(selist, lfirst_oid(l), perms);
	}
	return selist;
}

static List *__expandPgAttributeInheritance(List *selist, Oid relid, char *attname, uint32 perms)
{
	List *child_list = find_inheritance_children(relid);
	ListCell *l;

	foreach (l, child_list) {
		Form_pg_attribute attrForm;
		HeapTuple tuple;

		if (!attname) {
			/* attname == NULL means RECORD reference */
			selist = __addEvalPgAttribute(selist, lfirst_oid(l), false, 0, perms);
			selist = __expandPgAttributeInheritance(selist, lfirst_oid(l), NULL, perms);
			continue;
		}

		tuple = SearchSysCacheAttName(lfirst_oid(l), attname);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for attribute %s of relation %u",
				 attname, lfirst_oid(l));
		attrForm = (Form_pg_attribute) GETSTRUCT(tuple);
		selist = __addEvalPgAttribute(selist, lfirst_oid(l), false, attrForm->attnum, perms);
		selist = __expandPgAttributeInheritance(selist, lfirst_oid(l), attname, perms);

		ReleaseSysCache(tuple);
	}

	return selist;
}

static List *expandSEvalListInheritance(List *selist) {
	List *result = NIL;
	ListCell *l;

	foreach (l, selist) {
		SEvalItem *se = (SEvalItem *) lfirst(l);

		result = lappend(result, se);
		switch (se->tclass) {
		case SECCLASS_DB_TABLE:
			if (se->c.inh) {
				se->c.inh = false;
				result = __expandPgClassInheritance(result,
													se->c.relid,
													se->perms);
			}
			break;
		case SECCLASS_DB_COLUMN:
			if (se->a.inh) {
				Form_pg_attribute attrForm;
				HeapTuple tuple;

				se->a.inh = false;
				if (se->a.attno == 0) {
					result = __expandPgAttributeInheritance(result,
															se->a.relid,
															NULL,
															se->perms);
					break;
				}
				tuple = SearchSysCache(ATTNUM,
									   ObjectIdGetDatum(se->a.relid),
									   Int16GetDatum(se->a.attno),
									   0, 0);
				if (!HeapTupleIsValid(tuple))
					elog(ERROR, "SELinux: cache lookup failed for attribute %d of relation %u",
						 se->a.attno, se->a.relid);
				attrForm = (Form_pg_attribute) GETSTRUCT(tuple);

				result = __expandPgAttributeInheritance(result,
														se->a.relid,
														NameStr(attrForm->attname),
														se->perms);
				ReleaseSysCache(tuple);
			}
			break;
		}
	}
	return result;
}

static void execVerifyQuery(List *selist)
{
	ListCell *l;

	foreach (l, selist) {
		SEvalItem *se = lfirst(l);

		switch (se->tclass) {
		case SECCLASS_DB_TABLE:
			verifyPgClassPerms(se->c.relid, se->c.inh, se->perms);
			break;
		case SECCLASS_DB_COLUMN:
			verifyPgAttributePerms(se->a.relid, se->a.inh, se->a.attno, se->perms);
			break;
		case SECCLASS_DB_PROCEDURE:
			verifyPgProcPerms(se->p.funcid, se->perms);
			break;
		default:
			elog(ERROR, "SELinux: unexpected SEvalItem (tclass: %d)", se->tclass);
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
	selist = (List *) pstmt->pgaceItem;

	/* expand table inheritances */
	selist = expandSEvalListInheritance(selist);

	/* add checks for access via trigger function */
	foreach(l, pstmt->resultRelations) {
		Index rindex = lfirst_int(l);

		rte = rt_fetch(rindex, pstmt->rtable);
		Assert(IsA(rte, RangeTblEntry));

		selist = addEvalTriggerAccess(selist, rte->relid, rte->inh, pstmt->commandType);
	}
	execVerifyQuery(selist);
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

	selist = __addEvalPgClass(selist, RelationGetRelid(rel), false,
							  isFrom ? DB_TABLE__INSERT : DB_TABLE__SELECT);
	foreach (l, attNumList) {
		AttrNumber attnum = lfirst_int(l);

		selist = __addEvalPgAttribute(selist, RelationGetRelid(rel), false, attnum,
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

/* ----------------------------------------------------------
 * special cases in foreign key constraint
 * ---------------------------------------------------------- */
Oid sepgsqlPreparePlanCheck(Relation rel) {
	Oid pgace_saved = fnoid_sepgsql_tuple_perm;
	fnoid_sepgsql_tuple_perm = F_SEPGSQL_TUPLE_PERMS_ABORT;
	return pgace_saved;
}

void sepgsqlRestorePlanCheck(Relation rel, Oid pgace_saved) {
	fnoid_sepgsql_tuple_perm = pgace_saved;
}
