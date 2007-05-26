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

#define RTEMARK_SELECT        (1<<(N_ACL_RIGHTS))
#define RTEMARK_INSERT        (1<<(N_ACL_RIGHTS + 1))
#define RTEMARK_UPDATE        (1<<(N_ACL_RIGHTS + 2))
#define RTEMARK_DELETE        (1<<(N_ACL_RIGHTS + 3))
#define RTEMARK_RELABELFROM   (1<<(N_ACL_RIGHTS + 4))
#define RTEMARK_RELABELTO     (1<<(N_ACL_RIGHTS + 5))
#define RTEMARK_BLOB_READ     (1<<(N_ACL_RIGHTS + 6))
#define RTEMARK_BLOB_WRITE    (1<<(N_ACL_RIGHTS + 7))

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

/* local definitions of static functions. */
static List *sepgsqlWalkExpr(List *selist, queryChain *qc, Node *n);
static List *proxyRteRelation(List *selist, queryChain *qc, int rtindex, Node **quals);
static List *proxyRteSubQuery(List *selist, queryChain *qc, Query *query);
static List *proxyJoinTree(List *selist, queryChain *qc, Node *n, Node **quals);
static List *proxySetOperations(List *selist, queryChain *qc, Node *n);

/* -----------------------------------------------------------
 * addEvalXXXX -- add evaluation items into Query->SEvalItemList.
 * Those are used for execution phase.
 * ----------------------------------------------------------- */
static List *addEvalPgClass(List *selist, RangeTblEntry *rte, uint32 perms)
{
	ListCell *l;
	SEvalItem *se;

	rte->requiredPerms |= (perms & TABLE__SELECT ? RTEMARK_SELECT : 0);
	rte->requiredPerms |= (perms & TABLE__INSERT ? RTEMARK_INSERT : 0);
	rte->requiredPerms |= (perms & TABLE__UPDATE ? RTEMARK_UPDATE : 0);
	rte->requiredPerms |= (perms & TABLE__DELETE ? RTEMARK_DELETE : 0);

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_TABLE
			&& se->c.relid == rte->relid
			&& se->c.inh == rte->inh) {
			se->perms |= perms;
			return selist;
		}
	}
	se = makeNode(SEvalItem);
	se->tclass = SECCLASS_TABLE;
	se->perms = perms;
	se->c.relid = rte->relid;
	se->c.inh = rte->inh;
	return lappend(selist, se);
}

static List *addEvalPgAttribtue(List *selist, RangeTblEntry *rte, AttrNumber attno, uint32 perms)
{
	ListCell *l;
	SEvalItem *se;

	/* for 'security_context' */
	if (attno == SecurityAttributeNumber
		&& (perms & (COLUMN__UPDATE | COLUMN__INSERT)))
		rte->requiredPerms |= RTEMARK_RELABELFROM;

	/* for 'pg_largeobject' */
	if (rte->relid == LargeObjectRelationId
		&& attno == Anum_pg_largeobject_data) {
		if (perms & COLUMN__SELECT)
			rte->requiredPerms |= RTEMARK_BLOB_READ;
		if (perms & (COLUMN__UPDATE | COLUMN__INSERT))
			rte->requiredPerms |= RTEMARK_BLOB_WRITE;
	}

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_COLUMN
			&& se->a.relid == rte->relid
			&& se->a.inh == rte->inh
			&& se->a.attno == attno) {
            se->perms |= perms;
			return selist;
		}
	}

    se = makeNode(SEvalItem);
    se->tclass = SECCLASS_COLUMN;
    se->perms = perms;
    se->a.relid = rte->relid;
    se->a.inh = rte->inh;
    se->a.attno = attno;

    return lappend(selist, se);
}

static List *addEvalPgProc(List *selist, Oid funcid, uint32 perms)
{
	ListCell *l;
	SEvalItem *se;

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_PROCEDURE
			&& se->p.funcid == funcid) {
			se->perms |= perms;
			return selist;
		}
	}
	se = makeNode(SEvalItem);
	se->tclass = SECCLASS_PROCEDURE;
	se->perms = perms;
	se->p.funcid = funcid;

	return lappend(selist, se);
}

/* *******************************************************************************
 * walkExpr() -- walk on expression tree recursively to pick up and to construct
 * a SEvalItem list related to expression node.
 * It is evaluated at later phase.
 * *******************************************************************************/
static List *walkVarHelper(List *selist, queryChain *qc, Var *var)
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
		selist = addEvalPgClass(selist, rte, TABLE__SELECT);
		/* column:{select} */
		selist = addEvalPgAttribtue(selist, rte, var->varattno, COLUMN__SELECT);
		break;
	case RTE_JOIN:
		n = list_nth(rte->joinaliasvars, var->varattno - 1);
		selist = sepgsqlWalkExpr(selist, qc, n);
        break;
	case RTE_SUBQUERY:
		/* In normal cases, rte->relid equals zero for subquery.
		 * If rte->relid has none-zero value, it's rewritten subquery
		 * for outer join handling.
		 */
		if (rte->relid && var->varattno == var->varoattno) {
			Query *sqry = rte->subquery;
			ListCell *l;
			TargetEntry *tle;
			Var *svar;
			bool found = false;

			Assert(sqry->commandType == CMD_SELECT);
			Assert(list_length(sqry->rtable) == 1);
			Assert(((RangeTblEntry *) list_nth(sqry->rtable, 0))->rtekind == RTE_RELATION);
			Assert(((RangeTblEntry *) list_nth(sqry->rtable, 0))->relid == rte->relid);

			foreach (l, sqry->targetList) {
				tle = lfirst(l);

				Assert(IsA(tle->expr, Var));
				svar = (Var *) tle->expr;

				if (var->varattno == svar->varattno) {
					var->varattno = tle->resno;
					found = true;
					break;
				}
			}
			/* append pseudo reference */
			if (!found) {
				AttrNumber resno = list_length(sqry->targetList) + 1;

				svar = makeVar(1, var->varattno, var->vartype, var->vartypmod, 0);
				tle = makeTargetEntry((Expr *)svar, resno, NULL, false);
				var->varattno = resno;
				sqry->targetList = lappend(sqry->targetList, tle);
			}
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

	selist = addEvalPgProc(selist, oprform->oprcode, PROCEDURE__EXECUTE);
	/* NOTE: opr->oprrest and opr->oprjoin are internal use only
	 * and have no effect onto the data references, so we don't
	 * apply any checkings for them.
	 */
	ReleaseSysCache(tuple);

	return selist;
}

static List *sepgsqlWalkExpr(List *selist, queryChain *qc, Node *node)
{
	if (node == NULL)
		return selist;

	switch (nodeTag(node)) {
	case T_Const:
	case T_Param:
	case T_CaseTestExpr:
		/* do nothing */
		break;
	case T_List: {
		ListCell *l;

		foreach (l, (List *) node)
			selist = sepgsqlWalkExpr(selist, qc, (Node *) lfirst(l));
		break;
	}
	case T_Var: {
		selist = walkVarHelper(selist, qc, (Var *) node);
		break;
	}
	case T_FuncExpr: {
		FuncExpr *func = (FuncExpr *) node;

		selist = addEvalPgProc(selist, func->funcid, PROCEDURE__EXECUTE);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) func->args);
		break;
	}
	case T_Aggref: {
		Aggref *aggref = (Aggref *) node;

		selist = addEvalPgProc(selist, aggref->aggfnoid, PROCEDURE__EXECUTE);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aggref->args);
		break;
	}
	case T_OpExpr:
	case T_DistinctExpr:		/* typedef of OpExpr */
	case T_NullIfExpr:			/* typedef of OpExpr */
	{
		OpExpr *op = (OpExpr *) node;

		selist = walkOpExprHelper(selist, op->opno);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) op->args);
		break;
	}
	case T_ScalarArrayOpExpr: {
		ScalarArrayOpExpr *saop = (ScalarArrayOpExpr *) node;

		selist = walkOpExprHelper(selist, saop->opno);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) saop->args);
		break;
	}
	case T_BoolExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((BoolExpr *) node)->args);
		break;
	}
	case T_ArrayRef: {
		ArrayRef *aref = (ArrayRef *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refupperindexpr);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->reflowerindexpr);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refexpr);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refassgnexpr);
		break;
	}
	case T_SubLink: {
		SubLink *slink = (SubLink *) node;

		Assert(IsA(slink->subselect, Query));
		selist = sepgsqlWalkExpr(selist, qc, (Node *) slink->testexpr);
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
				selist = sepgsqlWalkExpr(selist, qc, (Node *) tle->expr);
				break;
			}
		}
		break;
	}
	case T_CoerceToDomain: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((CoerceToDomain *) node)->arg);
		break;
	}
	case T_CaseExpr: {
		CaseExpr *ce = (CaseExpr *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->arg);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->args);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->defresult);
		break;
	}
	case T_CaseWhen: {
		CaseWhen *casewhen = (CaseWhen *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) casewhen->expr);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) casewhen->result);
		break;
	}
	case T_RelabelType: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((RelabelType *) node)->arg);
		break;
	}
	case T_CoalesceExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((CoalesceExpr *) node)->args);
		break;
	}
	case T_MinMaxExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((MinMaxExpr *) node)->args);
		break;
	}
	case T_NullTest: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((NullTest *) node)->arg);
		break;
	}
	case T_BooleanTest: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((BooleanTest *) node)->arg);
		break;
	}
	case T_FieldSelect: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((FieldSelect *) node)->arg);
		break;
	}
	case T_FieldStore: {
		FieldStore *fstore = (FieldStore *) node;

		selist = sepgsqlWalkExpr(selist, qc, (Node *) fstore->arg);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) fstore->newvals);
		break;
	}
	case T_ArrayExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((ArrayExpr *) node)->elements);
		break;
	}
	case T_RowExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((RowExpr *) node)->args);
		break;
	}
	case T_RowCompareExpr: {
		RowCompareExpr *rce = (RowCompareExpr *) node;
		ListCell *l;

		foreach (l, rce->opnos)
			selist = walkOpExprHelper(selist, lfirst_oid(l));
		selist = sepgsqlWalkExpr(selist, qc, (Node *) rce->largs);
		selist = sepgsqlWalkExpr(selist, qc, (Node *) rce->rargs);
		break;
	}
	case T_ConvertRowtypeExpr: {
		selist = sepgsqlWalkExpr(selist, qc,
								 (Node *) ((ConvertRowtypeExpr *) node)->arg);
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
		sqry->targetList = NIL;

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
	uint32 perms = 0;

	query = getQueryFromChain(qc);
	rte = list_nth(query->rtable, rtindex - 1);
	rel = relation_open(rte->relid, AccessShareLock);
	tdesc = RelationGetDescr(rel);

	/* setup tclass and access vector */
	perms = 0;
	if (rte->requiredPerms & RTEMARK_SELECT)
		perms |= TUPLE__SELECT;
	if (rte->requiredPerms & RTEMARK_INSERT)
		perms |= TUPLE__INSERT;
	if (rte->requiredPerms & RTEMARK_UPDATE)
		perms |= TUPLE__UPDATE;
	if (rte->requiredPerms & RTEMARK_DELETE)
		perms |= TUPLE__DELETE;
	if (rte->requiredPerms & RTEMARK_RELABELFROM)
		perms |= TUPLE__RELABELFROM;
	if (rte->requiredPerms & RTEMARK_RELABELTO)
		perms |= TUPLE__RELABELTO;
	if (rte->requiredPerms & RTEMARK_BLOB_READ)
		perms |= BLOB__READ;
	if (rte->requiredPerms & RTEMARK_BLOB_WRITE)
		perms |= BLOB__WRITE;

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

	if (cmdType != CMD_SELECT) {
		rte = list_nth(query->rtable, query->resultRelation - 1);
		Assert(IsA(rte, RangeTblEntry) && rte->rtekind==RTE_RELATION);
		switch (cmdType) {
		case CMD_INSERT:
			selist = addEvalPgClass(selist, rte, TABLE__INSERT);
			break;
		case CMD_UPDATE:
			selist = addEvalPgClass(selist, rte, TABLE__UPDATE);
			break;
		case CMD_DELETE:
			selist = addEvalPgClass(selist, rte, TABLE__DELETE);
			break;
		default:
			selerror("commandType = %d should not be found here", cmdType);
			break;
		}
	}

	/* permission mark on the target columns */
	if (cmdType != CMD_DELETE) {
		foreach (l, query->targetList) {
			TargetEntry *te = lfirst(l);
			Assert(IsA(te, TargetEntry));

			selist = sepgsqlWalkExpr(selist, qc, (Node *) te->expr);

			/* mark insert/update target */
			if (cmdType==CMD_UPDATE || cmdType==CMD_INSERT) {
				uint32 perms = (cmdType == CMD_UPDATE
								? COLUMN__UPDATE
								: COLUMN__INSERT);
				if (te->resjunk) {
					if (!strcmp(te->resname, SECURITY_SYSATTR_NAME))
						selist = addEvalPgAttribtue(selist, rte, SecurityAttributeNumber, perms);
					continue;
				}
				selist = addEvalPgAttribtue(selist, rte, te->resno, perms);
			}
		}
	}

	/* permission mark on RETURNING clause, if necessary */
	foreach (l, query->returningList) {
		TargetEntry *te = lfirst(l);
		Assert(IsA(te, TargetEntry));
		selist = sepgsqlWalkExpr(selist, qc, (Node *) te->expr);
	}

	/* permission mark on the WHERE/HAVING clause */
	selist = sepgsqlWalkExpr(selist, qc, query->jointree->quals);
	selist = sepgsqlWalkExpr(selist, qc, query->havingQual);

	/* permission mark on the ORDER BY clause */
	// selist = sepgsqlWalkExpr(selist, qc, (Node *) query->sortClause);

	/* permission mark on the GROUP BY/HAVING clause */
	// selist = sepgsqlWalkExpr(selist, qc, (Node *) query->groupClause);

	/* permission mark on the UNION/INTERSECT/EXCEPT */
	selist = proxySetOperations(selist, qc, query->setOperations);

	/* append sepgsql_permission() on the FROM clause/USING clause
	 * for SELECT/UPDATE/DELETE statement.
	 * The target Relation of INSERT is noe necessary to append it
	 */
	selist = proxyJoinTree(selist, qc, (Node *) query->jointree,
						   &query->jointree->quals);

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
			selist = proxyRteSubQuery(selist, qc, rte->subquery);
			break;
		case RTE_FUNCTION: {
			FuncExpr *f = (FuncExpr *) rte->funcexpr;

			selist = sepgsqlWalkExpr(selist, qc, (Node *) f);
			selist = sepgsqlWalkExpr(selist, qc, (Node *) f->args);
			break;
		}
		case RTE_VALUES:
			selist = sepgsqlWalkExpr(selist, qc, (Node *) rte->values_lists);
			break;
		default:
			selerror("rtekind = %d should not be found fromList", rte->rtekind);
			break;
		}
	} else if (IsA(n, FromExpr)) {
		FromExpr *f = (FromExpr *)n;
		ListCell *l;

		selist = sepgsqlWalkExpr(selist, qc, f->quals);
		foreach (l, f->fromlist)
			selist = proxyJoinTree(selist, qc, lfirst(l), quals);
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) n;

		selist = sepgsqlWalkExpr(selist, qc, j->quals);
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
	selist = sepgsqlWalkExpr(selist, &qcData, (Node *) estmt->params);
	query->pgaceList = selist;

	return list_make1(query);
}

static Query *convertTruncateToDelete(Relation rel)
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

	sepgsqlProxyQuery(query);

	return query;
}

static List *proxyTruncateStmt(Query *query)
{
	TruncateStmt *stmt = (TruncateStmt *) query->utilityStmt;
	Relation rel;
	Query *subqry;
	ListCell *l;
	List *subquery_list = NIL, *subquery_lids = NIL;

	/* resolve the relation names */
	foreach (l, stmt->relations) {
		RangeVar *rv = lfirst(l);

		rel = heap_openrv(rv, AccessShareLock);
		subqry = convertTruncateToDelete(rel);
		subquery_list = lappend(subquery_list, subqry);
		subquery_lids = lappend_oid(subquery_lids, RelationGetRelid(rel));
		heap_close(rel, NoLock);

		selnotice("virtual TRUNCATE %s", RelationGetRelationName(rel));
	}

	if (stmt->behavior == DROP_CASCADE) {
		subquery_lids = heap_truncate_find_FKs(subquery_lids);
		foreach (l, subquery_lids) {
			Oid relid = lfirst_oid(l);

			rel = heap_open(relid, AccessShareLock);
			subqry = convertTruncateToDelete(rel);
			subquery_list = lappend(subquery_list, subqry);
			heap_close(rel, NoLock);
		}
	}
	return subquery_list;
}

List *sepgsqlProxyQuery(Query *query)
{
	List *new_list = NIL;

	if (!sepgsqlIsEnabled())
		return list_make1(query);

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

List *sepgsqlProxyQueryList(List *queryList)
{
	ListCell *l;
	List *new_list = NIL;

	if (!sepgsqlIsEnabled())
		return queryList;

	foreach (l, queryList) {
		Query *query = lfirst(l);

		new_list = list_concat(new_list,
							   sepgsqlProxyQuery(query));
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
static void verifyPgClassPermsInheritances(Oid relid, uint32 perms);

static void verifyPgClassPerms(Oid relid, bool inh, uint32 perms)
{
	Form_pg_class pgclass;
	HeapTuple tuple;

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
						   SECCLASS_TABLE,
						   perms,
						   NameStr(pgclass->relname));
	ReleaseSysCache(tuple);

	/* check child relations, if necessary */
	if (inh)
		verifyPgClassPermsInheritances(relid, perms);
}

static void verifyPgClassPermsInheritances(Oid relid, uint32 perms)
{
	List *chld_list;
	ListCell *l;

	chld_list = find_inheritance_children(relid);
	foreach (l, chld_list) {
		Oid chld_oid = lfirst_oid(l);

		verifyPgClassPerms(chld_oid, true, perms);
	}
}

static void verifyPgAttributePermsInheritances(Oid parent_relid, char *attname, uint32 perms);

static void verifyPgAttributePerms(Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	HeapTuple tuple;
	Form_pg_class pgclass;
	Form_pg_attribute pgattr;

	tuple = SearchSysCache(RELOID,
							ObjectIdGetDatum(relid),
							0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("RELOID cache lookup failed (relid=%u)", relid);
	pgclass = (Form_pg_class) GETSTRUCT(tuple);
	if (pgclass->relkind != RELKIND_RELATION) {
		//selnotice("'%s' is not a general relation", NameStr(pgclass->relname));
		ReleaseSysCache(tuple);
		return;
	}
	ReleaseSysCache(tuple);

	/* 2. verify column perms */
	if (attno == 0) {
		/* RECORD type permission check */
		Relation pg_attr;
		ScanKeyData skey;
		SysScanDesc sd;

		ScanKeyInit(&skey,
					Anum_pg_attribute_attrelid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(relid));

		pg_attr = heap_open(AttributeRelationId, AccessShareLock);
		sd = systable_beginscan(pg_attr, AttributeRelidNumIndexId,
								true, SnapshotNow, 1, &skey);
		while ((tuple = systable_getnext(sd)) != NULL) {
			pgattr = (Form_pg_attribute) GETSTRUCT(tuple);
			sepgsql_avc_permission(sepgsqlGetClientContext(),
								   HeapTupleGetSecurity(tuple),
								   SECCLASS_COLUMN,
								   perms,
								   NameStr(pgattr->attname));
		}
		systable_endscan(sd);
		heap_close(pg_attr, AccessShareLock);

		return;
	}

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("ATTNUM cache lookup failed (relid=%u, attno=%d)", relid, attno);

	/* check column:{required permissions} */
	pgattr = (Form_pg_attribute) GETSTRUCT(tuple);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_COLUMN,
						   perms,
						   NameStr(pgattr->attname));

	/* check child relations, if necesasry */
	if (inh)
		verifyPgAttributePermsInheritances(relid, NameStr(pgattr->attname), perms);

	ReleaseSysCache(tuple);
}

static void verifyPgAttributePermsInheritances(Oid parent_relid, char *attname, uint32 perms)
{
	List *chld_list;
	ListCell *l;

	chld_list = find_inheritance_children(parent_relid);
	foreach (l, chld_list) {
		Form_pg_attribute attr;
		HeapTuple tuple;
		Oid chld_oid;

		chld_oid = lfirst_oid(l);
		tuple = SearchSysCacheAttName(chld_oid, attname);
		if (!HeapTupleIsValid(tuple)) {
			selnotice("relation %u dose not have attribute '%s'", chld_oid, attname);
			continue;
		}
		attr = (Form_pg_attribute) GETSTRUCT(tuple);
		verifyPgAttributePerms(chld_oid, true, attr->attnum, perms);
		ReleaseSysCache(tuple);
	}
}

static void verifyPgProcPerms(Oid funcid, uint32 perms)
{
	HeapTuple tuple;
	Oid newcon;
	Form_pg_proc pgproc;

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
		perms |= PROCEDURE__ENTRYPOINT;

	/* check procedure executiong permission */
	pgproc = (Form_pg_proc) GETSTRUCT(tuple);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_PROCEDURE,
						   perms,
						   NameStr(pgproc->proname));

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

void sepgsqlVerifyQuery(Query *query)
{
	ListCell *l;

	foreach (l, query->pgaceList) {
		SEvalItem *se = lfirst(l);

		switch (se->tclass) {
		case SECCLASS_TABLE:
			verifyPgClassPerms(se->c.relid, se->c.inh, se->perms);
			break;
		case SECCLASS_COLUMN:
			verifyPgAttributePerms(se->a.relid, se->a.inh, se->a.attno, se->perms);
			break;
		case SECCLASS_PROCEDURE:
			verifyPgProcPerms(se->p.funcid, se->perms);
			break;
		default:
			selerror("unknown SEvalItem (tclass=%u)", se->tclass);
			break;
		}
	}
}

/* *******************************************************************************
 * PGACE hooks: we cannon the following hooks in sepgsqlHooks.c because they
 * refers static defined variables in sepgsqlProxy.c
 * *******************************************************************************/

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
	case SECCLASS_TABLE:
		newnode->c.relid = oldnode->c.relid;
		newnode->c.inh = oldnode->c.inh;
		break;
	case SECCLASS_COLUMN:
		newnode->a.relid = oldnode->a.relid;
		newnode->a.attno = oldnode->a.attno;
		newnode->a.inh = oldnode->a.inh;
		break;
	case SECCLASS_PROCEDURE:
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
	case SECCLASS_TABLE:
		appendStringInfo(str, ":c.relid %u", seitem->c.relid);
		appendStringInfo(str, ":c.inh %s", seitem->c.inh ? "true" : "false");
		break;
	case SECCLASS_COLUMN:
		appendStringInfo(str, ":a.relid %u", seitem->c.relid);
		appendStringInfo(str, ":a.inh %s", seitem->c.inh ? "true" : "false");
		appendStringInfo(str, ":a.attno %u", seitem->c.inh);
		break;
	case SECCLASS_PROCEDURE:
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
