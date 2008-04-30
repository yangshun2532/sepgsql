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
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "nodes/makefuncs.h"
#include "optimizer/plancat.h"
#include "parser/parse_relation.h"
#include "parser/parse_target.h"
#include "security/pgace.h"
#include "storage/lock.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

/* SE-PostgreSQL Evaluation Item */
#define T_SEvalItem		(T_TIDBitmap + 1)		/* must be unique identifier */

typedef struct SEvalItem {
	NodeTag type;
	uint16 tclass;
	uint32 perms;
	union {
		struct {
			Oid relid;
			bool inh;
		} c;  /* for pg_class */
		struct {
			Oid relid;
			bool inh;
			AttrNumber attno;
		} a;  /* for pg_attribute */
		struct {
			Oid funcid;
		} p;  /* for pg_proc */
	};
} SEvalItem;

/* query stack definition for outer references */
typedef struct queryChain {
	struct queryChain *parent;
	Query *tail;
} queryChain;

static inline queryChain *upperQueryChain(queryChain *qc, int lvup) {
	while (lvup > 0) {
		Assert(!!qc->parent);
		qc = qc->parent;
		lvup--;
	}
	return qc;
}

static inline Query *getQueryFromChain(queryChain *qc) {
	return qc->tail;
}

/* static definitions for proxy functions */
static List *proxyRteRelation(List *selist, queryChain *qc, int rtindex, Node **quals);
static List *proxyRteSubQuery(List *selist, queryChain *qc, Query *query);
static List *proxyJoinTree(List *selist, queryChain *qc, Node *n, Node **quals);
static List *proxySetOperations(List *selist, queryChain *qc, Node *n);

/* static  */
static List *sepgsqlWalkExpr(List *selist, queryChain *qc, Node *n, int flags);
#define WKFLAG_INTERNAL_USE         (0x0001)

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
	rte->requiredPerms |= (perms & DB_TABLE__USE    ? SEPGSQL_PERMS_USE    : 0);
	rte->requiredPerms |= (perms & DB_TABLE__SELECT ? SEPGSQL_PERMS_SELECT : 0);
	rte->requiredPerms |= (perms & DB_TABLE__INSERT ? SEPGSQL_PERMS_INSERT : 0);
	rte->requiredPerms |= (perms & DB_TABLE__UPDATE ? SEPGSQL_PERMS_UPDATE : 0);
	rte->requiredPerms |= (perms & DB_TABLE__DELETE ? SEPGSQL_PERMS_DELETE : 0);

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
	/* for 'security_context' */
	if (attno == SecurityAttributeNumber
		&& (perms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT)))
		rte->requiredPerms |= SEPGSQL_PERMS_RELABELFROM;

	/* for 'pg_largeobject' */
	if (rte->relid == LargeObjectRelationId
		&& attno == Anum_pg_largeobject_data) {
		if (perms & DB_COLUMN__SELECT)
			rte->requiredPerms |= SEPGSQL_PERMS_READ;
		if (perms & (DB_COLUMN__UPDATE | DB_COLUMN__INSERT))
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
 * walkExpr() -- walk on expression tree recursively to pick up and to construct
 * a SEvalItem list related to expression node.
 * It is evaluated at later phase.
 * *******************************************************************************/
static List *walkVarHelper(List *selist, queryChain *qc, Var *var, int flags)
{
	RangeTblEntry *rte;
	Query *query;
	Node *n;

	Assert(IsA(var, Var));
	if (!qc)
		selerror("we could not use Var node in parameter list");

	qc = upperQueryChain(qc, var->varlevelsup);
	query = getQueryFromChain(qc);
	rte = list_nth(query->rtable, var->varno - 1);
	Assert(IsA(rte, RangeTblEntry));

	switch (rte->rtekind) {
	case RTE_RELATION:
		/* table:{select} */
		selist = addEvalPgClass(selist, rte,
								(flags & WKFLAG_INTERNAL_USE)
								? DB_TABLE__USE : DB_TABLE__SELECT);
		/* column:{select} */
		selist = addEvalPgAttribute(selist, rte, var->varattno,
									(flags & WKFLAG_INTERNAL_USE)
									? DB_COLUMN__USE : DB_COLUMN__SELECT);
		break;
	case RTE_JOIN:
		n = list_nth(rte->joinaliasvars, var->varattno - 1);
		selist = sepgsqlWalkExpr(selist, qc, n, flags);
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
					selerror("dropped column is accessed (relid=%u, attno=%d)",
							 rte->relid, var->varattno);
				svar = (Var *) tle->expr;
			}
			/* table:{select} or [use} */
			selist = addEvalPgClass(selist, srte,
									(flags & WKFLAG_INTERNAL_USE)
									? DB_TABLE__USE : DB_TABLE__SELECT);
			/* column:{select} or {use}*/
			selist = addEvalPgAttribute(selist, srte, svar->varattno,
										(flags & WKFLAG_INTERNAL_USE)
										? DB_COLUMN__USE : DB_COLUMN__SELECT);
		}
		break;
	case RTE_SPECIAL:
	case RTE_FUNCTION:
	case RTE_VALUES:
		break;
	default:
		selerror("unrecognized rtekind (%d)", rte->rtekind);
		break;
	}
	return selist;
}

static List *walkOpExprHelper(List *selist, Oid opid)
{
	HeapTuple tuple;
	Form_pg_operator oprform;

	tuple = SearchSysCache(OPEROID,
						   ObjectIdGetDatum(opid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for OPEROID = %u", opid);
	oprform = (Form_pg_operator) GETSTRUCT(tuple);

	selist = addEvalPgProc(selist, oprform->oprcode, DB_PROCEDURE__EXECUTE);
	/* NOTE: opr->oprrest and opr->oprjoin are internal use only
	 * and have no effect onto the data references, so we don't
	 * apply any checkings for them.
	 */
	ReleaseSysCache(tuple);

	return selist;
}

static List *sepgsqlWalkExpr(List *selist, queryChain *qc, Node *node, int flags)
{
	if (node == NULL)
		return selist;

	switch (nodeTag(node)) {
	case T_Const:
	case T_Param:
	case T_CaseTestExpr:
	case T_CoerceToDomainValue:
	case T_SetToDefault:
		/* do nothing */
		break;
	case T_List: {
		ListCell *l;

		foreach (l, (List *) node)
			selist = sepgsqlWalkExpr(selist, qc, (Node *) lfirst(l), flags);
		break;
	}
	case T_Var: {
		selist = walkVarHelper(selist, qc, (Var *) node, flags);
		break;
	}
	case T_FuncExpr: {
		FuncExpr *func = (FuncExpr *) node;

		selist = addEvalPgProc(selist, func->funcid, DB_PROCEDURE__EXECUTE);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) func->args, flags);
		break;
	}
	case T_Aggref: {
		Aggref *aggref = (Aggref *) node;

		selist = addEvalPgProc(selist, aggref->aggfnoid, DB_PROCEDURE__EXECUTE);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aggref->args, flags);
		break;
	}
	case T_OpExpr:
	case T_DistinctExpr:		/* typedef of OpExpr */
	case T_NullIfExpr:			/* typedef of OpExpr */
	{
		OpExpr *op = (OpExpr *) node;

		selist = walkOpExprHelper(selist, op->opno);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) op->args, flags);
		break;
	}
	case T_ScalarArrayOpExpr: {
		ScalarArrayOpExpr *saop = (ScalarArrayOpExpr *) node;

		selist = walkOpExprHelper(selist, saop->opno);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) saop->args, flags);
		break;
	}
	case T_BoolExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((BoolExpr *) node)->args, flags);
		break;
	}
	case T_ArrayRef: {
		ArrayRef *aref = (ArrayRef *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refupperindexpr, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->reflowerindexpr, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refexpr, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refassgnexpr, flags);
		break;
	}
	case T_SubLink: {
		SubLink *slink = (SubLink *) node;

		Assert(IsA(slink->subselect, Query));
		selist = sepgsqlWalkExpr(selist, qc, (Node *) slink->testexpr, flags);
		selist = proxyRteSubQuery(selist, qc, (Query *) slink->subselect);
		break;
	}
	case T_SortClause:
	case T_GroupClause:		/* typedef of SortClause */
	{
		SortClause *sort = (SortClause *) node;
		Query *query = getQueryFromChain(qc);
		ListCell *l;

		foreach (l, query->targetList) {
			TargetEntry *tle = (TargetEntry *) lfirst(l);
			Assert(IsA(tle, TargetEntry));
			if (tle->ressortgroupref == sort->tleSortGroupRef) {
				selist = sepgsqlWalkExpr(selist, qc, (Node *) tle->expr, flags);
				break;
			}
		}
		break;
	}
	case T_CoerceToDomain: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((CoerceToDomain *) node)->arg, flags);
		break;
	}
	case T_CaseExpr: {
		CaseExpr *ce = (CaseExpr *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->arg, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->args, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->defresult, flags);
		break;
	}
	case T_CaseWhen: {
		CaseWhen *casewhen = (CaseWhen *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) casewhen->expr, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) casewhen->result, flags);
		break;
	}
	case T_RelabelType: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((RelabelType *) node)->arg, flags);
		break;
	}
	case T_CoalesceExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((CoalesceExpr *) node)->args, flags);
		break;
	}
	case T_MinMaxExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((MinMaxExpr *) node)->args, flags);
		break;
	}
	case T_NullTest: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((NullTest *) node)->arg, flags);
		break;
	}
	case T_BooleanTest: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((BooleanTest *) node)->arg, flags);
		break;
	}
	case T_FieldSelect: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((FieldSelect *) node)->arg, flags);
		break;
	}
	case T_FieldStore: {
		FieldStore *fstore = (FieldStore *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) fstore->arg, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) fstore->newvals, flags);
		break;
	}
	case T_ArrayExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((ArrayExpr *) node)->elements, flags);
		break;
	}
	case T_RowExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((RowExpr *) node)->args, flags);
		break;
	}
	case T_RowCompareExpr: {
		RowCompareExpr *rce = (RowCompareExpr *) node;
		ListCell *l;

		foreach (l, rce->opnos)
			selist = walkOpExprHelper(selist, lfirst_oid(l));
		selist = sepgsqlWalkExpr(selist, qc, (Node *) rce->largs, flags);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) rce->rargs, flags);
		break;
	}
	case T_ConvertRowtypeExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((ConvertRowtypeExpr *) node)->arg, flags);
		break;
	}
	default:
		selnotice("node(%d) is ignored => %s", nodeTag(node), nodeToString(node));
		break;
	}
	return selist;
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
		selerror("relation (oid: %u) does not exist", relid);

	classForm = (Form_pg_class) GETSTRUCT(reltup);
	relnatts = classForm->relnatts;
	for (attno = 1; attno <= relnatts; attno++) {
		atttup = SearchSysCache(ATTNUM,
								ObjectIdGetDatum(relid),
								Int16GetDatum(attno),
								0, 0);
		if (!HeapTupleIsValid(atttup))
			selerror("attribute %u of relation '%s' does not exist",
					 attno, NameStr(classForm->relname));
		attrForm = (Form_pg_attribute) GETSTRUCT(atttup);
		if (attrForm->attisdropped) {
			expr = (Expr *) makeNullConst(INT4OID);
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
		selerror("unrecognized node type (%d) in query->jointree", nodeTag(n));
	}
}

static List *proxyRteRelation(List *selist, queryChain *qc, int rtindex, Node **quals)
{
	Query *query;
	RangeTblEntry *rte;
	Relation rel;
	TupleDesc tdesc;
	uint32 perms;

	query = getQueryFromChain(qc);
	rte = list_nth(query->rtable, rtindex - 1);
	rel = relation_open(rte->relid, AccessShareLock);
	tdesc = RelationGetDescr(rel);

	/* append sepgsql_tuple_perm(relid, record, perms) */
	perms = rte->requiredPerms & SEPGSQL_PERMS_ALL;
	if (perms) {
		Var *v1, *v2, *v4;
		Const *c3;
		FuncExpr *func;

		/* 1st arg : Oid of the target relation */
		v1 = makeVar(rtindex, TableOidAttributeNumber, OIDOID, -1, 0);

		/* 2nd arg : Security Attribute of tuple */
		v2 = makeVar(rtindex, SecurityAttributeNumber, OIDOID, -1, 0);
		
		/* 3rd arg : permission set */
		c3 = makeConst(INT4OID, sizeof(int32), Int32GetDatum(perms), false, true);

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
	relation_close(rel, NoLock);

	return selist;
}

static List *proxyRteOuterJoin(List *selist, queryChain *qc, Query *query)
{
	queryChain qcData;
	ListCell *l;

	qcData.parent = qc;
	qcData.tail = query;
	qc = &qcData;

	selist = proxyRteRelation(selist, qc, 1, &query->jointree->quals);

	/* clean-up polluted RangeTblEntry */
	foreach (l, query->rtable) {
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(l);
		rte->requiredPerms &= ~SEPGSQL_PERMS_ALL;
	}

	return selist;
}

static List *__checkSelectTargets(List *selist, Query *query, Node *node)
{
	if (node == NULL)
		return selist;

	if (IsA(node, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) node;
		RangeTblEntry *rte = list_nth(query->rtable, rtr->rtindex - 1);

		switch (rte->rtekind) {
		case RTE_RELATION:
			selist = addEvalPgClass(selist, rte, DB_TABLE__SELECT);
			break;
		case RTE_SUBQUERY:
			if (rte->relid) {
				Query *sqry = rte->subquery;
				RangeTblEntry *srte = list_nth(sqry->rtable, 0);

				selist = addEvalPgClass(selist, srte, DB_TABLE__SELECT);
			}
			break;
		default:
			/* do nothing */
			break;
		}
	} else if (IsA(node, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) node;

		selist = __checkSelectTargets(selist, query, j->larg);
		selist = __checkSelectTargets(selist, query, j->rarg);
	} else if (IsA(node, FromExpr)) {
		FromExpr *fm = (FromExpr *)node;
		ListCell *l;

		foreach (l, fm->fromlist)
			selist = __checkSelectTargets(selist, query, lfirst(l));
	} else {
		elog(ERROR, "SELinux: unexpected node type (%d) at Query->fromlist", nodeTag(node));
	}
    return selist;
}

static List *proxyRteSubQuery(List *selist, queryChain *qc, Query *query)
{
	CmdType cmdType = query->commandType;
	RangeTblEntry *rte = NULL;
	queryChain qcData;
	ListCell *l;

	/* query chain setup */
	qcData.parent = qc;
	qcData.tail = query;
	qc = &qcData;

	/* rewrite outer join */
	rewriteOuterJoinTree((Node *) query->jointree, query, false);

	if (cmdType == CMD_SELECT) {
		selist = __checkSelectTargets(selist, query, (Node *)query->jointree);
	} else {
		rte = list_nth(query->rtable, query->resultRelation - 1);
		Assert(IsA(rte, RangeTblEntry) && rte->rtekind==RTE_RELATION);
		switch (cmdType) {
		case CMD_INSERT:
			selist = addEvalPgClass(selist, rte, DB_TABLE__INSERT);
			break;
		case CMD_UPDATE:
			selist = addEvalPgClass(selist, rte, DB_TABLE__UPDATE);
			break;
		case CMD_DELETE:
			selist = addEvalPgClass(selist, rte, DB_TABLE__DELETE);
			break;
		default:
			selerror("commandType = %d should not be found here", cmdType);
			break;
		}
	}

	/* permission mark on the target columns */
	if (cmdType != CMD_DELETE) {
		foreach (l, query->targetList) {
			TargetEntry *tle = lfirst(l);
			bool is_security_attr = false;
			Assert(IsA(tle, TargetEntry));

			if (tle->resjunk && !strcmp(tle->resname, SECURITY_SYSATTR_NAME))
				is_security_attr = true;

			/* pure junk target entries */
			if (tle->resjunk && !is_security_attr) {
				selist = sepgsqlWalkExpr(selist, qc, (Node *) tle->expr,
										 WKFLAG_INTERNAL_USE);
				continue;
			}

			selist = sepgsqlWalkExpr(selist, qc, (Node *) tle->expr, 0);
			/* mark insert/update target */
			if (cmdType==CMD_UPDATE || cmdType==CMD_INSERT) {
				uint32 perms = (cmdType == CMD_UPDATE
								? DB_COLUMN__UPDATE : DB_COLUMN__INSERT);
				if (is_security_attr) {
					selist = addEvalPgAttribute(selist,
												rte,
												SecurityAttributeNumber,
												perms);
					continue;
				}
				selist = addEvalPgAttribute(selist, rte, tle->resno, perms);
			}
		}
	}

	/* permission mark on RETURNING clause, if necessary */
	foreach (l, query->returningList) {
		TargetEntry *te = lfirst(l);
		Assert(IsA(te, TargetEntry));
		selist = sepgsqlWalkExpr(selist, qc, (Node *) te->expr, 0);
	}

	/* permission mark on the WHERE/HAVING clause */
	selist = sepgsqlWalkExpr(selist, qc, query->jointree->quals,
							 WKFLAG_INTERNAL_USE);
	selist = sepgsqlWalkExpr(selist, qc, query->havingQual,
							 WKFLAG_INTERNAL_USE);

	/* permission mark on the ORDER BY clause */
	//selist = sepgsqlWalkExpr(selist, qc, (Node *) query->sortClause, WKFLAG_INTERNAL_USE);

	/* permission mark on the GROUP BY/HAVING clause */
	//selist = sepgsqlWalkExpr(selist, qc, (Node *) query->groupClause, WKFLAG_INTERNAL_USE);

	/* permission mark on the UNION/INTERSECT/EXCEPT */
	selist = proxySetOperations(selist, qc, query->setOperations);

	/* append sepgsql_permission() on the FROM clause/USING clause
	 * for SELECT/UPDATE/DELETE statement.
	 * The target Relation of INSERT is noe necessary to append it
	 */
	selist = proxyJoinTree(selist, qc, (Node *) query->jointree,
						   &query->jointree->quals);

	/* clean-up polluted RangeTblEntry */
	foreach (l, query->rtable) {
		rte = (RangeTblEntry *) lfirst(l);
		rte->requiredPerms &= ~SEPGSQL_PERMS_ALL;
	}

	return selist;
}

static List *proxyJoinTree(List *selist, queryChain *qc, Node *n, Node **quals)
{
	Query *query = getQueryFromChain(qc);

	if (n == NULL)
		return selist;

	if (IsA(n, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) n;
		RangeTblEntry *rte = list_nth(query->rtable, rtr->rtindex - 1);
		Assert(IsA(rte, RangeTblEntry));

		switch (rte->rtekind) {
		case RTE_RELATION:
			selist = proxyRteRelation(selist, qc, rtr->rtindex, quals);
			break;
		case RTE_SUBQUERY:
			selist = (rte->relid
					  ? proxyRteOuterJoin(selist, qc, rte->subquery)
					  : proxyRteSubQuery(selist, qc, rte->subquery));
			break;
		case RTE_FUNCTION: {
			FuncExpr *f = (FuncExpr *) rte->funcexpr;

			selist = sepgsqlWalkExpr(selist, qc, (Node *) f, 0);
			selist = sepgsqlWalkExpr(selist, qc, (Node *) f->args, 0);
			break;
		}
		case RTE_VALUES:
			selist = sepgsqlWalkExpr(selist, qc, (Node *) rte->values_lists, 0);
			break;
		default:
			selerror("rtekind = %d should not be found fromList", rte->rtekind);
			break;
		}
	} else if (IsA(n, FromExpr)) {
		FromExpr *f = (FromExpr *)n;
		ListCell *l;

		selist = sepgsqlWalkExpr(selist, qc, f->quals, WKFLAG_INTERNAL_USE);
		foreach (l, f->fromlist)
			selist = proxyJoinTree(selist, qc, lfirst(l), quals);
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) n;

		selist = sepgsqlWalkExpr(selist, qc, j->quals, WKFLAG_INTERNAL_USE);
		selist = proxyJoinTree(selist, qc, j->larg, &j->quals);
		selist = proxyJoinTree(selist, qc, j->rarg, &j->quals);
	} else {
		selerror("unrecognized node type (%d) in query->jointree", nodeTag(n));
	}
	return selist;
}

static List *proxySetOperations(List *selist, queryChain *qc, Node *n)
{
	Query *query = getQueryFromChain(qc);

	if (n == NULL)
		return selist;

	if (IsA(n, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) n;
		RangeTblEntry *rte = list_nth(query->rtable, rtr->rtindex - 1);

		Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_SUBQUERY);

		selist = proxyRteSubQuery(selist, qc, rte->subquery);
    } else if (IsA(n, SetOperationStmt)) {
		SetOperationStmt *op = (SetOperationStmt *) n;

		selist = proxySetOperations(selist, qc, (Node *) op->larg);
		selist = proxySetOperations(selist, qc, (Node *) op->rarg);
    } else {
		selerror("setOperationsTree contains => %s", nodeToString(n));
    }

	return selist;
}

static List *proxyGeneralQuery(Query *query)
{
	List *selist = NIL;

	selist = proxyRteSubQuery(selist, NULL, query);
	query->pgaceList = selist;

	return list_make1(query);
}

static List *proxyExecuteStmt(Query *query)
{
	List *selist = NIL;
	ExecuteStmt *estmt = (ExecuteStmt *) query->utilityStmt;
	queryChain qcData;

	Assert(nodeTag(query->utilityStmt) == T_ExecuteStmt);

	qcData.parent = NULL;
	qcData.tail = query;
	selist = sepgsqlWalkExpr(selist, &qcData, (Node *) estmt->params, 0);
	query->pgaceList = selist;

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

	selnotice("virtual TRUNCATE %s", RelationGetRelationName(rel));

	return sepgsqlProxyQuery(query);
}

static List *proxyTruncateStmt(Query *query)
{
	TruncateStmt *stmt = (TruncateStmt *) query->utilityStmt;
	Relation rel;
	ListCell *l;
	List *subquery_list = NIL;
	List *subquery_lids = NIL;

	/* resolve the relation names */
	foreach (l, stmt->relations) {
		RangeVar *rv = lfirst(l);

		rel = heap_openrv(rv, AccessShareLock);
		subquery_list = list_concat(subquery_list,
									convertTruncateToDelete(rel));
		subquery_lids = lappend_oid(subquery_lids,
									RelationGetRelid(rel));
		heap_close(rel, AccessShareLock);
	}

	if (stmt->behavior == DROP_CASCADE) {
		subquery_lids = heap_truncate_find_FKs(subquery_lids);
		foreach (l, subquery_lids) {
			Oid relid = lfirst_oid(l);

			rel = heap_open(relid, AccessShareLock);
			subquery_list = list_concat(subquery_list,
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
		selerror("unknown command type (=%d) found",
				 query->commandType);
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

	/* prevent to modify pg_security directly */
	if (relid == SecurityRelationId
		&& (perms & (DB_TABLE__UPDATE | DB_TABLE__INSERT | DB_TABLE__DELETE)) != 0)
		selerror("user cannot modify pg_security directly, for security reason");

	/* check table:{required permissions} */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("RELOID cache lookup failed (relid=%u)", relid);
	pgclass = (Form_pg_class) GETSTRUCT(tuple);

	if (pgclass->relkind != RELKIND_RELATION) {
		//selnotice("%s is not a general relation", NameStr(pgclass->relname));
		ReleaseSysCache(tuple);
		return;
	}

	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_TABLE,
						   perms,
						   sepgsqlGetTupleName(RelationRelationId, tuple));
	ReleaseSysCache(tuple);
}

static void verifyPgAttributePerms(Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	HeapTuple tuple;
	Form_pg_class classForm;
	Form_pg_attribute attrForm;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("RELOID cache lookup failed (relid=%u)", relid);
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
								   sepgsqlGetTupleName(AttributeRelationId, tuple));
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
		selerror("ATTNUM cache lookup failed (relid=%u, attno=%d)", relid, attno);

	/* check column:{required permissions} */
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_COLUMN,
						   perms,
						   sepgsqlGetTupleName(AttributeRelationId, tuple));
	ReleaseSysCache(tuple);
}

static void verifyPgProcPerms(Oid funcid, uint32 perms)
{
	HeapTuple tuple;
	Oid newcon;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(funcid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for procedure %d", funcid);

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
						   sepgsqlGetTupleName(ProcedureRelationId, tuple));

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
			selerror("relation %u does not have attribute %s",
                     lfirst_oid(l), attname);
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
					selerror("relation %u attribute %d not found", se->a.relid, se->a.attno);
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
			selerror("unknown SEvalItem (tclass=%u)", se->tclass);
			break;
		}
	}
}

void sepgsqlVerifyQuery(Query *query)
{
	List *selist = copyObject(query->pgaceList);

	/* expand table inheritances */
	selist = expandSEvalListInheritance(selist);

	/* add checks for access via trigger function */
	if (query->resultRelation > 0) {
		RangeTblEntry *rte = (RangeTblEntry *) list_nth(query->rtable,
														query->resultRelation - 1);
		Assert(IsA(rte, RangeTblEntry));
		selist = addEvalTriggerAccess(selist, rte->relid, rte->inh, query->commandType);
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

bool sepgsqlCopyToTuple(Relation rel, HeapTuple tuple)
{
	return sepgsqlCheckTuplePerms(rel, tuple, NULL, SEPGSQL_PERMS_SELECT, false);
}

bool sepgsqlCopyFromTuple(Relation rel, HeapTuple tuple)
{
	Oid tcontext = HeapTupleGetSecurity(tuple);

	if (tcontext == InvalidOid) {
		/* implicit labeling */
		tcontext = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, tcontext);
	}
	return sepgsqlCheckTuplePerms(rel, tuple, NULL, SEPGSQL_PERMS_INSERT, false);
}

/* ----------------------------------------------------------
 * node copy/print hooks
 * ---------------------------------------------------------- */
Node *sepgsqlCopyObject(Node *__oldnode) {
	SEvalItem *oldnode, *newnode;

	if (nodeTag(__oldnode) != T_SEvalItem)
		return NULL;
	oldnode = (SEvalItem *) __oldnode;

	newnode = makeNode(SEvalItem);
	newnode->tclass = oldnode->tclass;
	newnode->perms = oldnode->perms;
	switch (oldnode->tclass) {
	case SECCLASS_DB_TABLE:
		newnode->c.relid = oldnode->c.relid;
		newnode->c.inh = oldnode->c.inh;
		break;
	case SECCLASS_DB_COLUMN:
		newnode->a.relid = oldnode->a.relid;
		newnode->a.attno = oldnode->a.attno;
		newnode->a.inh = oldnode->a.inh;
		break;
	case SECCLASS_DB_PROCEDURE:
		newnode->p.funcid = oldnode->p.funcid;
		break;
	default:
		selerror("unrecognized SEvalItem node (tclass: %d)", oldnode->tclass);
		break;
	}
	return (Node *) newnode;
}

bool sepgsqlOutObject(StringInfo str, Node *node) {
	SEvalItem *seitem = (SEvalItem *) node;

	if (nodeTag(node) != T_SEvalItem)
		return false;

	appendStringInfoString(str, "SEVALITEM");
	appendStringInfo(str, ":tclass %u", seitem->tclass);
	appendStringInfo(str, ":perms %u", seitem->perms);
	switch(seitem->tclass) {
	case SECCLASS_DB_TABLE:
		appendStringInfo(str, ":c.relid %u", seitem->c.relid);
		appendStringInfo(str, ":c.inh %s", seitem->c.inh ? "true" : "false");
		break;
	case SECCLASS_DB_COLUMN:
		appendStringInfo(str, ":a.relid %u", seitem->c.relid);
		appendStringInfo(str, ":a.inh %s", seitem->c.inh ? "true" : "false");
		appendStringInfo(str, ":a.attno %u", seitem->c.inh);
		break;
	case SECCLASS_DB_PROCEDURE:
		appendStringInfo(str, ":p.funcid %u", seitem->p.funcid);
		break;
	default:
		selerror("unrecognized SEvalItem node (tclass: %d)", seitem->tclass);
		break;
	}
	return true;
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
