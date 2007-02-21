/*
 * src/backend/security/sepgsqlProxy.c
 *   SE-PostgreSQL Query Proxy function to walk on query node tree
 *   and append tuple filter.
 *
 * Copyright KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

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
#include "security/sepgsql.h"
#include "security/sepgsql_internal.h"
#include "storage/lock.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"

#define RTEMARK_SELECT        (1<<(N_ACL_RIGHTS))
#define RTEMARK_INSERT        (1<<(N_ACL_RIGHTS + 1))
#define RTEMARK_UPDATE        (1<<(N_ACL_RIGHTS + 2))
#define RTEMARK_DELETE        (1<<(N_ACL_RIGHTS + 3))
#define RTEMARK_RELABELFROM   (1<<(N_ACL_RIGHTS + 4))
#define RTEMARK_RELABELTO     (1<<(N_ACL_RIGHTS + 5))

/* local definitions of static functions. */
static List *proxyRteRelation(List *selist, Query *query, int rtindex, Node **quals);
static List *proxyRteSubQuery(List *selist, Query *query);
static List *proxyJoinTree(List *selist, Query *query, Node *n, Node **quals);
static List *proxySetOperations(List *selist, Query *query, Node *n);

/* -----------------------------------------------------------
 * 
 * 
 * 
 * 
 * -----------------------------------------------------------
 */
static List *addEvalPgClass(List *selist, Oid relid, bool inh, uint32 perms)
{
	ListCell *l;
	SEvalItem *se;

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_TABLE
			&& se->c.relid == relid
			&& se->c.inh == inh) {
			se->perms |= perms;
			return selist;
		}
	}
	se = makeNode(SEvalItem);
	se->tclass = SECCLASS_TABLE;
	se->perms = perms;
	se->c.relid = relid;
	se->c.inh = inh;
	return lappend(selist, se);
}

static List *addEvalPgAttribtue(List *selist, Oid relid, bool inh, AttrNumber attno, uint32 perms)
{
	ListCell *l;
	SEvalItem *se;

	foreach (l, selist) {
		se = (SEvalItem *) lfirst(l);
		if (se->tclass == SECCLASS_COLUMN
			&& se->a.relid == relid
			&& se->a.inh == inh
			&& se->a.attno == attno) {
            se->perms |= perms;
			return selist;
		}
	}

    se = makeNode(SEvalItem);
    se->tclass = SECCLASS_COLUMN;
    se->perms = perms;
    se->a.relid = relid;
    se->a.inh = inh;
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
			se->p.funcid |= perms;
			return selist;
		}
	}
	se = makeNode(SEvalItem);
	se->tclass = SECCLASS_PROCEDURE;
	se->perms = perms;
	se->p.funcid = funcid;

	return lappend(selist, se);
}

static List *walkVar(List *selist, Query *query, Var *var)
{
	RangeTblEntry *rte;
	Node *n;

	Assert(IsA(var, Var));
	if (!query)
		selerror("we could not use Var node in parameter list");

	rte = list_nth(query->rtable, var->varno - 1);
	Assert(IsA(rte, RangeTblEntry));
	switch (rte->rtekind) {
	case RTE_RELATION:
		rte->requiredPerms |= RTEMARK_SELECT;
		/* table:{select} */
		selist = addEvalPgClass(selist, rte->relid, rte->inh, TABLE__SELECT);
		/* column:{select} */
		selist = addEvalPgAttribtue(selist, rte->relid, rte->inh, var->varattno, COLUMN__SELECT);
		break;
	case RTE_JOIN:
		n = list_nth(rte->joinaliasvars, var->varattno - 1);
        selist = sepgsqlWalkExpr(selist, query, n);
        break;
	default:
		selnotice("rtekind = %d is ignored", rte->rtekind);
		break;
	}
	return selist;
}

static List *walkFuncExpr(List *selist, Query *query, FuncExpr *func)
{
	Assert(IsA(func, FuncExpr));

	selist = addEvalPgProc(selist, func->funcid, PROCEDURE__EXECUTE);
	selist = sepgsqlWalkExpr(selist, query, (Node *) func->args);

	return selist;
}

static List *walkBoolExpr(List *selist, Query *query, BoolExpr *expr)
{
	Assert(IsA(expr, BoolExpr));
	return sepgsqlWalkExpr(selist, query, (Node *) expr->args);
}

static List *walkOpExpr(List *selist, Query *query, OpExpr *n)
{
	HeapTuple tuple;
	Form_pg_operator opr;

	Assert(IsA(n, OpExpr));

	tuple = SearchSysCache(OPEROID,
						   ObjectIdGetDatum(n->opno),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("OPEROID cache lookup failed (opno=%u)", n->opno);
	opr = (Form_pg_operator) GETSTRUCT(tuple);

	selist = addEvalPgProc(selist, opr->oprcode, PROCEDURE__EXECUTE);
	/* NOTE: opr->oprrest and opr->oprjoin are internal use only
	 * and have no effect onto the data references, so we don't
	 * apply any checkings for them.
	 */
	ReleaseSysCache(tuple);

	selist = sepgsqlWalkExpr(selist, query, (Node *) n->args);

	return selist;
}

static List *walkAggref(List *selist, Query *query, Aggref *aggref)
{
	Assert(IsA(aggref, Aggref));
	selist = addEvalPgProc(selist, aggref->aggfnoid, PROCEDURE__EXECUTE);
	selist = sepgsqlWalkExpr(selist, query, (Node *) aggref->args);
	return selist;
}

static List *walkSubLink(List *selist, Query *query, SubLink *slink)
{
	Assert(IsA(slink, SubLink));
	Assert(IsA(slink->subselect, Query));

	selist = proxyRteSubQuery(selist, (Query *) slink->subselect);

	return selist;
}

static List *walkList(List *selist, Query *query, List *list)
{
	ListCell *l;

	Assert(IsA(list, List));
	foreach (l, list)
		selist = sepgsqlWalkExpr(selist, query, lfirst(l));

	return selist;
}

static List *walkSortClause(List *selist, Query *query, SortClause *sortcl)
{
	ListCell *l;

	Assert(IsA(sortcl, SortClause) || IsA(sortcl, GroupClause));
	foreach (l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		if (te->ressortgroupref == sortcl->tleSortGroupRef) {
			selist = sepgsqlWalkExpr(selist, query, (Node *) te->expr);
			break;
		}
	}
	return selist;
}

static List *walkCoerceToDomain(List *selist, Query *query, CoerceToDomain *cd)
{
	return sepgsqlWalkExpr(selist, query, (Node *) cd->arg);
}

static List *walkCaseExpr(List *selist, Query *query, CaseExpr *ce)
{
	ListCell *l;

	selist = sepgsqlWalkExpr(selist, query, (Node *) ce->arg);
	foreach(l, ce->args)
		selist = sepgsqlWalkExpr(selist, query, (Node *) lfirst(l));
	selist = sepgsqlWalkExpr(selist, query, (Node *) ce->defresult);
	return selist;
}

static List *walkCaseWhen(List *selist, Query *query, CaseWhen *cw)
{
	selist = sepgsqlWalkExpr(selist, query, (Node *) cw->expr);
	selist = sepgsqlWalkExpr(selist, query, (Node *) cw->result);
	return selist;
}

static List *walkRelabelType(List *selist, Query *query, RelabelType *rt)
{
	return sepgsqlWalkExpr(selist, query, (Node *) rt->arg);
}

static List *walkCoalesceExpr(List *selist, Query *query, CoalesceExpr *ce)
{
	ListCell *l;
	foreach (l, ce->args)
		selist = sepgsqlWalkExpr(selist, query, (Node *) lfirst(l));
	return selist;
}

static List *walkMinMaxExpr(List *selist, Query *query, MinMaxExpr *mme)
{
	ListCell *l;
	foreach (l, mme->args)
		selist = sepgsqlWalkExpr(selist, query, (Node *) lfirst(l));
	return selist;
}

static List *walkNullTest(List *selist, Query *query, NullTest *nt)
{
	return sepgsqlWalkExpr(selist, query, (Node *) nt->arg);
}

List *sepgsqlWalkExpr(List *selist, Query *query, Node *n)
{
	if (n == NULL)
		return selist;

	switch (nodeTag(n)) {
	case T_Const:
		/* do nothing */
		break;
	case T_Var:
		selist = walkVar(selist, query, (Var *) n);
		break;
	case T_FuncExpr:
		selist = walkFuncExpr(selist, query, (FuncExpr *) n);
		break;
	case T_BoolExpr:
		selist = walkBoolExpr(selist, query, (BoolExpr *) n);
		break;
	case T_NullIfExpr:
	case T_OpExpr:
		selist = walkOpExpr(selist, query, (OpExpr *) n);
		break;
	case T_Aggref:
		selist = walkAggref(selist, query, (Aggref *) n);
		break;
	case T_SubLink:
		selist = walkSubLink(selist, query, (SubLink *) n);
		break;
	case T_SortClause:
	case T_GroupClause:  /* GroupClause is typedef'ed by SortClause */
		selist = walkSortClause(selist, query, (SortClause *) n);
		break;
	case T_List:
		selist = walkList(selist, query, (List *) n);
		break;
	case T_CoerceToDomain:
		selist = walkCoerceToDomain(selist, query, (CoerceToDomain *)n);
		break;
	case T_CaseExpr:
		selist = walkCaseExpr(selist, query, (CaseExpr *)n);
		break;
	case T_CaseWhen:
		selist = walkCaseWhen(selist, query, (CaseWhen *)n);
		break;
	case T_RelabelType:
		selist = walkRelabelType(selist, query, (RelabelType *)n);
		break;
	case T_CoalesceExpr:
		selist = walkCoalesceExpr(selist, query, (CoalesceExpr *)n);
		break;
	case T_MinMaxExpr:
		selist = walkMinMaxExpr(selist, query, (MinMaxExpr *)n);
		break;
	case T_NullTest:
		selist = walkNullTest(selist, query, (NullTest *)n);
		break;
	default:
		selnotice("Node(%d) is ignored => %s", nodeTag(n), nodeToString(n));
		break;
	}
	return selist;
}

/* -----------------------------------------------------------
 * 
 *
 *
 */
static Oid funcoid_sepgsql_tuple_perm = F_SEPGSQL_TUPLE_PERMS;

static List *proxyRteRelation(List *selist, Query *query, int rtindex, Node **quals)
{
	RangeTblEntry *rte;
	Relation rel;
	TupleDesc tdesc;
	uint32 perms = 0;

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
		func = makeFuncExpr(funcoid_sepgsql_tuple_perm, BOOLOID,
							list_make3(v1, v2, c3), COERCE_DONTCARE);
		if (*quals == NULL) {
			*quals = (Node *) func;
		} else {
			*quals = (Node *) makeBoolExpr(AND_EXPR, list_make2(func, *quals));
		}
		selnotice("append sepgsql_permission(tableoid, %s, 0x%08x)",
				  RelationGetRelationName(rel), perms);
	}
	relation_close(rel, NoLock);
	
	return selist;
}

static List *proxyRteSubQuery(List *selist, Query *query)
{
	CmdType cmdType = query->commandType;
	RangeTblEntry *rte = NULL;
	ListCell *l;

	if (cmdType != CMD_SELECT) {
		rte = list_nth(query->rtable, query->resultRelation - 1);
		Assert(IsA(rte, RangeTblEntry) && rte->rtekind==RTE_RELATION);
		switch (cmdType) {
		case CMD_INSERT:
			rte->requiredPerms |= RTEMARK_INSERT;
			selist = addEvalPgClass(selist, rte->relid, rte->inh, TABLE__INSERT);
			break;
		case CMD_UPDATE:
			rte->requiredPerms |= RTEMARK_UPDATE;
			selist = addEvalPgClass(selist, rte->relid, rte->inh, TABLE__UPDATE);
			break;
		case CMD_DELETE:
			rte->requiredPerms |= RTEMARK_DELETE;
			selist = addEvalPgClass(selist, rte->relid, rte->inh, TABLE__DELETE);
			break;
		default:
			selerror("commandType = %d should not be found here", cmdType);
			break;
		}
	}

	/* permission mark on the target columns */
	if (cmdType != CMD_DELETE) {
		uint32 perms = 0;
		if (cmdType == CMD_INSERT)
			perms |= COLUMN__INSERT;
		if (cmdType == CMD_UPDATE)
			perms |= COLUMN__UPDATE;

		foreach (l, query->targetList) {
			TargetEntry *te = lfirst(l);
			Assert(IsA(te, TargetEntry));

			selist = sepgsqlWalkExpr(selist, query, (Node *) te->expr);

			/* mark insert/update target */
			if (te->resjunk) {
				if (!strcmp(te->resname, SECURITY_ATTR)) {
					selist = addEvalPgAttribtue(selist, rte->relid, rte->inh,
												SecurityAttributeNumber, perms);
					rte->requiredPerms |= RTEMARK_RELABELFROM;
				}
				continue;
			}
			if (cmdType==CMD_UPDATE || cmdType==CMD_INSERT) {
				selist = addEvalPgAttribtue(selist, rte->relid, rte->inh,
											te->resno, perms);
			}
		}
	}

	/* permission mark on RETURNING clause, if necessary */
	foreach (l, query->returningList) {
		TargetEntry *te = lfirst(l);
		Assert(IsA(te, TargetEntry));
		selist = sepgsqlWalkExpr(selist, query, (Node *) te->expr);
	}

	/* permission mark on the WHERE/HAVING clause */
	selist = sepgsqlWalkExpr(selist, query, query->jointree->quals);
	selist = sepgsqlWalkExpr(selist, query, query->havingQual);

	/* permission mark on the ORDER BY clause */
	// selist = sepgsqlWalkExpr(selist, query, (Node *) query->sortClause);

	/* permission mark on the GROUP BY/HAVING clause */
	// selist = sepgsqlWalkExpr(selist, query, (Node *) query->groupClause);

	/* append sepgsql_permission() on the FROM clause/USING clause
	 * for SELECT/UPDATE/DELETE statement.
	 * The target Relation of INSERT is noe necessary to append it
	 */
	selist = proxyJoinTree(selist, query, (Node *) query->jointree,
							 &query->jointree->quals);

	/* permission mark on the UNION/INTERSECT/EXCEPT */
	selist = proxySetOperations(selist, query, query->setOperations);

	return selist;
}

static List *proxyJoinTree(List *selist, Query *query, Node *n, Node **quals)
{
	if (n == NULL)
		return selist;

	if (IsA(n, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) n;
		RangeTblEntry *rte = list_nth(query->rtable, rtr->rtindex - 1);
		Assert(IsA(rte, RangeTblEntry));

		switch (rte->rtekind) {
		case RTE_RELATION:
			selist = proxyRteRelation(selist, query, rtr->rtindex, quals);
			break;
		case RTE_SUBQUERY:
			selist = proxyRteSubQuery(selist, rte->subquery);
			break;
		case RTE_FUNCTION: {
			FuncExpr *f = (FuncExpr *) rte->funcexpr;

			selist = sepgsqlWalkExpr(selist, query, (Node *) f);
			selist = sepgsqlWalkExpr(selist, query, (Node *) f->args);
			break;
		}
		case RTE_VALUES:
			selist = sepgsqlWalkExpr(selist, query, (Node *) rte->values_lists);
			break;
		default:
			selerror("rtekind = %d should not be found fromList", rte->rtekind);
			break;
		}
	} else if (IsA(n, FromExpr)) {
		FromExpr *f = (FromExpr *)n;
		ListCell *l;

		foreach (l, f->fromlist)
			selist = proxyJoinTree(selist, query, lfirst(l), quals);
	} else if (IsA(n, JoinExpr)) {
		JoinExpr *j = (JoinExpr *) n;

		selist = proxyJoinTree(selist, query, j->larg, &j->quals);
		selist = proxyJoinTree(selist, query, j->rarg, &j->quals);
	} else {
		selerror("unrecognized node type (%d) in query->jointree", nodeTag(n));
	}
	return selist;
}

static List *proxySetOperations(List *selist, Query *query, Node *n)
{
	if (n == NULL)
		return selist;

	if (IsA(n, RangeTblRef)) {
		RangeTblRef *rtr = (RangeTblRef *) n;
		RangeTblEntry *rte = list_nth(query->rtable, rtr->rtindex - 1);

		Assert(IsA(rte, RangeTblEntry) && rte->rtekind == RTE_SUBQUERY);

		selist = proxyRteSubQuery(selist, query);
    } else if (IsA(n, SetOperationStmt)) {
		SetOperationStmt *op = (SetOperationStmt *) n;

		selist = proxySetOperations(selist, query, (Node *) op->larg);
		selist = proxySetOperations(selist, query, (Node *) op->rarg);
    } else {
		selerror("setOperationsTree contains => %s", nodeToString(n));
    }

	return selist;
}

static List *proxyGeneralQuery(Query *query)
{
	List *selist = NIL;

	selist = proxyRteSubQuery(selist, query);
	query->SEvalItemList = selist;

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
		default:
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

	foreach (l, queryList) {
		Query *query = lfirst(l);

		new_list = list_concat(new_list,
							   sepgsqlProxyQuery(query));
	}
	return new_list;
}

/* special cases when Foreign Key processing */
void *sepgsqlForeignKeyPrepare(const char *querystr, int nargs, Oid *argtypes)
{
	Oid saved_funcoid = funcoid_sepgsql_tuple_perm;
	void *qplan;

	funcoid_sepgsql_tuple_perm = F_SEPGSQL_TUPLE_PERMS_ABORT;
	PG_TRY();
	{
		qplan = SPI_prepare(querystr, nargs, argtypes);
	}
	PG_CATCH();
	{
		funcoid_sepgsql_tuple_perm = saved_funcoid;
		PG_RE_THROW();
	}
	PG_END_TRY();
	funcoid_sepgsql_tuple_perm = saved_funcoid;

	return qplan;
}



