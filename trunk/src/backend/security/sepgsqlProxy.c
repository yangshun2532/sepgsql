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

/* query stack definition for outer references */
typedef struct queryChain {
	struct queryChain *parent;
	Query *tail;
} queryChain;

static inline Query *upperQueryChain(queryChain *qc, int lvup) {
	while (lvup > 0) {
		Assert(qc->parent);
		qc = qc->parent;
		lvup--;
	}
	return qc->tail;
}

static inline Query *tailQueryChain(queryChain *qc) {
	return upperQueryChain(qc, 0);
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
/* -----------------------------------------------------------
 * walkXXXX() -- walk on the Query tree recursively to check
 * refered expr, and push EvalItem for later evaluation.
 * ----------------------------------------------------------- */
static List *walkVar(List *selist, queryChain *qc, Var *var)
{
	RangeTblEntry *rte;
	Query *query;
	Node *n;

	Assert(IsA(var, Var));
	if (!qc)
		selerror("we could not use Var node in parameter list");

	query = upperQueryChain(qc, var->varlevelsup);
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
		if (var->varattno < 0)
			selerror("subquery does not have system column");
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

static List *walkFuncExpr(List *selist, queryChain *qc, FuncExpr *func)
{
	Assert(IsA(func, FuncExpr));

	selist = addEvalPgProc(selist, func->funcid, PROCEDURE__EXECUTE);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) func->args);

	return selist;
}

static List *walkBoolExpr(List *selist, queryChain *qc, BoolExpr *expr)
{
	Assert(IsA(expr, BoolExpr));
	return sepgsqlWalkExpr(selist, qc, (Node *) expr->args);
}

static List *__walkOpExprHelper(List *selist, Oid opid)
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

static List *walkOpExpr(List *selist, queryChain *qc, OpExpr *n)
{
	selist = __walkOpExprHelper(selist, n->opno);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) n->args);
	return selist;
}

static List *walkScalarArrayOpExpr(List *selist, queryChain *qc, ScalarArrayOpExpr *sao)
{
	selist = __walkOpExprHelper(selist, sao->opno);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) sao->args);
	return selist;
}

static List *walkAggref(List *selist, queryChain *qc, Aggref *aggref)
{
	Assert(IsA(aggref, Aggref));
	selist = addEvalPgProc(selist, aggref->aggfnoid, PROCEDURE__EXECUTE);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) aggref->args);
	return selist;
}

static List *walkSubLink(List *selist, queryChain *qc, SubLink *slink)
{
	Assert(IsA(slink, SubLink));
	Assert(IsA(slink->subselect, Query));

	selist = sepgsqlWalkExpr(selist, qc, (Node *) slink->testexpr);
	selist = proxyRteSubQuery(selist, qc, (Query *) slink->subselect);

	return selist;
}

static List *walkList(List *selist, queryChain *qc, List *list)
{
	ListCell *l;

	Assert(IsA(list, List));
	foreach (l, list)
		selist = sepgsqlWalkExpr(selist, qc, lfirst(l));

	return selist;
}

static List *walkSortClause(List *selist, queryChain *qc, SortClause *sortcl)
{
	Query *query = tailQueryChain(qc);
	ListCell *l;

	Assert(IsA(sortcl, SortClause) || IsA(sortcl, GroupClause));
	foreach (l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		if (te->ressortgroupref == sortcl->tleSortGroupRef) {
			selist = sepgsqlWalkExpr(selist, qc, (Node *) te->expr);
			break;
		}
	}
	return selist;
}

static List *walkCoerceToDomain(List *selist, queryChain *qc, CoerceToDomain *cd)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) cd->arg);
}

static List *walkCaseExpr(List *selist, queryChain *qc, CaseExpr *ce)
{
	ListCell *l;

	selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->arg);
	foreach(l, ce->args)
		selist = sepgsqlWalkExpr(selist, qc, (Node *) lfirst(l));
	selist = sepgsqlWalkExpr(selist, qc, (Node *) ce->defresult);
	return selist;
}

static List *walkCaseWhen(List *selist, queryChain *qc, CaseWhen *cw)
{
	selist = sepgsqlWalkExpr(selist, qc, (Node *) cw->expr);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) cw->result);
	return selist;
}

static List *walkRelabelType(List *selist, queryChain *qc, RelabelType *rt)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) rt->arg);
}

static List *walkCoalesceExpr(List *selist, queryChain *qc, CoalesceExpr *ce)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) ce->args);
}

static List *walkMinMaxExpr(List *selist, queryChain *qc, MinMaxExpr *mme)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) mme->args);
}

static List *walkNullTest(List *selist, queryChain *qc, NullTest *nt)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) nt->arg);
}

static List *walkBooleanTest(List *selist, queryChain *qc, BooleanTest *bt)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) bt->arg);
}

static List *walkFieldSelect(List *selist, queryChain *qc, FieldSelect *fselect)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) fselect->arg);
}

static List *walkFieldStore(List *selist, queryChain *qc, FieldStore *fstore)
{
	selist = sepgsqlWalkExpr(selist, qc, (Node *) fstore->arg);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) fstore->newvals);
	return selist;
}

static List *walkArrayExpr(List *selist, queryChain *qc, ArrayExpr *ae)
{
	return sepgsqlWalkExpr(selist, qc, (Node *) ae->elements);
}

static List *walkArrayRef(List *selist, queryChain *qc, ArrayRef *aref)
{
	selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refupperindexpr);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->reflowerindexpr);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refexpr);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) aref->refassgnexpr);
	return selist;
}

static List *walkRowExpr(List *selist, queryChain *qc, RowExpr *row)
{
	selist = sepgsqlWalkExpr(selist, qc, (Node *) row->args);
	return selist;
}

static List *walkRowCompareExpr(List *selist, queryChain *qc, RowCompareExpr *rce)
{
	ListCell *l;

	foreach(l, rce->opnos)
		selist = __walkOpExprHelper(selist, lfirst_oid(l));
	selist = sepgsqlWalkExpr(selist, qc, (Node *) rce->largs);
	selist = sepgsqlWalkExpr(selist, qc, (Node *) rce->rargs);

	return selist;
}

static List *sepgsqlWalkExpr(List *selist, queryChain *qc, Node *n)
{
	if (n == NULL)
		return selist;

	switch (nodeTag(n)) {
	case T_Const:
	case T_Param:
	case T_CaseTestExpr:
		/* do nothing */
		break;
	case T_Var:
		selist = walkVar(selist, qc, (Var *) n);
		break;
	case T_FuncExpr:
		selist = walkFuncExpr(selist, qc, (FuncExpr *) n);
		break;
	case T_ScalarArrayOpExpr:
		selist = walkScalarArrayOpExpr(selist, qc, (ScalarArrayOpExpr *) n);
		break;
	case T_BoolExpr:
		selist = walkBoolExpr(selist, qc, (BoolExpr *) n);
		break;
	case T_NullIfExpr:
	case T_OpExpr:
		selist = walkOpExpr(selist, qc, (OpExpr *) n);
		break;
	case T_Aggref:
		selist = walkAggref(selist, qc, (Aggref *) n);
		break;
	case T_ArrayRef:
		selist = walkArrayRef(selist, qc, (ArrayRef *) n);
		break;
	case T_SubLink:
		selist = walkSubLink(selist, qc, (SubLink *) n);
		break;
	case T_SortClause:
	case T_GroupClause:  /* GroupClause is typedef'ed by SortClause */
		selist = walkSortClause(selist, qc, (SortClause *) n);
		break;
	case T_List:
		selist = walkList(selist, qc, (List *) n);
		break;
	case T_CoerceToDomain:
		selist = walkCoerceToDomain(selist, qc, (CoerceToDomain *) n);
		break;
	case T_CaseExpr:
		selist = walkCaseExpr(selist, qc, (CaseExpr *) n);
		break;
	case T_CaseWhen:
		selist = walkCaseWhen(selist, qc, (CaseWhen *) n);
		break;
	case T_RelabelType:
		selist = walkRelabelType(selist, qc, (RelabelType *) n);
		break;
	case T_CoalesceExpr:
		selist = walkCoalesceExpr(selist, qc, (CoalesceExpr *) n);
		break;
	case T_MinMaxExpr:
		selist = walkMinMaxExpr(selist, qc, (MinMaxExpr *) n);
		break;
	case T_NullTest:
		selist = walkNullTest(selist, qc, (NullTest *) n);
		break;
	case T_BooleanTest:
		selist = walkBooleanTest(selist, qc, (BooleanTest *) n);
		break;
	case T_FieldSelect:
		selist = walkFieldSelect(selist, qc, (FieldSelect *) n);
		break;
	case T_FieldStore:
		selist = walkFieldStore(selist, qc, (FieldStore *) n);
		break;
	case T_ArrayExpr:
		selist = walkArrayExpr(selist, qc, (ArrayExpr *)n);
		break;
	case T_RowExpr:
		selist = walkRowExpr(selist, qc, (RowExpr *) n);
		break;
	case T_RowCompareExpr:
		selist = walkRowCompareExpr(selist, qc, (RowCompareExpr *)n);
		break;
	default:
		selnotice("Node(%d) is ignored => %s", nodeTag(n), nodeToString(n));
		break;
	}
	return selist;
}

/* -----------------------------------------------------------
 * proxyRteXXXX -- check any relation type including general
 * relation, join relation and subquery.
 * ----------------------------------------------------------- */
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
	ParseState *pstate;
	Query *sqry;
	FromExpr *frm;
	ColumnRef *cref;
	ResTarget *res;

	if (IsA(n, RangeTblRef)) {
		if (!is_outer_join)
			return;

		rtr = (RangeTblRef *) n;
		rte = list_nth(query->rtable, rtr->rtindex - 1);
		Assert(IsA(rte, RangeTblEntry));
		if (rte->rtekind != RTE_RELATION)
			return;

		/* setup pstate */
		pstate = make_parsestate(NULL);
		pstate->p_paramtypes = NULL;
		pstate->p_numparams = 0;
		pstate->p_variableparams = false;

		/* setup Query */
		sqry = makeNode(Query);
		sqry->commandType = CMD_SELECT;

		/* pseudo FROM clause */
		srte = copyObject(rte);
		srtr = makeNode(RangeTblRef);
		srtr->rtindex = 1;
		pstate->p_rtable = lappend(pstate->p_rtable, srte);
		pstate->p_joinlist = lappend(pstate->p_joinlist, srtr);
		pstate->p_relnamespace = lappend(pstate->p_relnamespace, srte);
		pstate->p_varnamespace = lappend(pstate->p_varnamespace, srte);

		/* pseudo targetList */
		cref = makeNode(ColumnRef);
		cref->fields = list_make1(makeString("*"));
		cref->location = -1;

		res = makeNode(ResTarget);
		res->name = NULL;
		res->indirection = NIL;
		res->val = (Node *) cref;
		res->location = -1;

		sqry->targetList = transformTargetList(pstate, list_make1(res));

		/* rest of setting up */
		sqry->rtable = pstate->p_rtable;
		frm = makeNode(FromExpr);
		frm->fromlist = pstate->p_joinlist;
		frm->quals = NULL;
		sqry->jointree = frm;
		sqry->hasSubLinks = false;
		sqry->hasAggs = false;
		pfree(pstate);

		/* rewrite parent RangeTblEntry */
		rte->rtekind = RTE_SUBQUERY;
		rte->relid = InvalidOid;
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

	query = tailQueryChain(qc);
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
		Var *v1, *v2;
		Const *c3;
		FuncExpr *func;

		/* 1st arg : Oid of the target relation */
		v1 = makeVar(rtindex, TableOidAttributeNumber, OIDOID, -1, 0);
		
		/* 2nd arg : RECORD of the target relation */
		v2 = makeVar(rtindex, 0, RelationGetForm(rel)->reltype, -1, 0);

		/* 3rd arg : permission set */
		c3 = makeConst(INT4OID, sizeof(int32), Int32GetDatum(perms), false, true);

		/* append sepgsql_tuple_perm */
		func = makeFuncExpr(fnoid_sepgsql_tuple_perm, BOOLOID,
							list_make3(v1, v2, c3), COERCE_DONTCARE);
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
			//rte->requiredPerms |= RTEMARK_INSERT;
			selist = addEvalPgClass(selist, rte, TABLE__INSERT);
			break;
		case CMD_UPDATE:
			//rte->requiredPerms |= RTEMARK_UPDATE;
			selist = addEvalPgClass(selist, rte, TABLE__UPDATE);
			break;
		case CMD_DELETE:
			//rte->requiredPerms |= RTEMARK_DELETE;
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
	Query *query = tailQueryChain(qc);

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

		foreach (l, f->fromlist)
			selist = proxyJoinTree(selist, qc, lfirst(l), quals);
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) n;

		selist = proxyJoinTree(selist, qc, j->larg, &j->quals);
		selist = proxyJoinTree(selist, qc, j->rarg, &j->quals);
	} else {
		selerror("unrecognized node type (%d) in query->jointree", nodeTag(n));
	}
	return selist;
}

static List *proxySetOperations(List *selist, queryChain *qc, Node *n)
{
	Query *query = tailQueryChain(qc);

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

Oid sepgsqlPreparePlanCheck(Relation rel) {
	Oid pgace_saved = fnoid_sepgsql_tuple_perm;
	fnoid_sepgsql_tuple_perm = F_SEPGSQL_TUPLE_PERMS_ABORT;
	return pgace_saved;
}

void sepgsqlRestorePlanCheck(Relation rel, Oid pgace_saved) {
	fnoid_sepgsql_tuple_perm = pgace_saved;
}
