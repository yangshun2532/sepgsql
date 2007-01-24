/*
 * src/backend/selinux/expr.c
 *   SE-PostgreSQL Expr walking implementation.
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "sepgsql.h"
#include "utils/syscache.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static void walkVar(Query *query, bool do_check, Var *var)
{
	RangeTblEntry *rte;
	HeapTuple tup;
	Form_pg_attribute attr;
	char *audit;
	int rc;

	Assert(IsA(var, Var));

	rte = (RangeTblEntry *) list_nth(query->rtable, var->varno - 1);
	Assert(IsA(rte, RangeTblEntry));

	switch (rte->rtekind) {
	case RTE_RELATION:
		tup = SearchSysCache(ATTNUM,
							 ObjectIdGetDatum(rte->relid),
							 Int16GetDatum(var->varattno),
							 0, 0);
		if (!HeapTupleIsValid(tup))
			selerror("cache lookup failed (relid=%u, attno=%d)",
					 rte->relid, var->varattno);
		attr = (Form_pg_attribute) GETSTRUCT(tup);
		if (!sepgsqlAttributeIsPsid(attr)) {
			rte->access_vector |= TABLE__SELECT;
			if (do_check) {
				rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
											attr->attselcon,
											SECCLASS_COLUMN,
											COLUMN__SELECT,
											&audit);
				sepgsql_audit(rc, audit, NameStr(attr->attname));
			}
		}
		ReleaseSysCache(tup);
		break;
	case RTE_JOIN:
		var = list_nth(rte->joinaliasvars, var->varattno - 1);
		sepgsqlWalkExpr(query, do_check, (Node *) var);
		break;
	default:
		seldebug("rtekind = %u is ignored", rte->rtekind);
		break;
	}
}

static void checkFunctionPerm(Oid funcid)
{
	Form_pg_proc proc;
	HeapTuple tup;
	psid newcon;
	uint32 perms;
	char *audit;
	int rc;

	tup = SearchSysCache(PROCOID,
						 ObjectIdGetDatum(funcid),
						 0, 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed (procid=%u)", funcid);
	proc = (Form_pg_proc) GETSTRUCT(tup);
	newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   proc->proselcon,
								   SECCLASS_PROCESS);
	perms = PROCEDURE__EXECUTE;
	if (sepgsqlGetClientPsid() != newcon)
		perms |= PROCEDURE__ENTRYPOINT;
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								proc->proselcon,
								SECCLASS_PROCEDURE,
								perms,
								&audit);

	if (sepgsqlGetClientPsid() != newcon) {
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									newcon,
									SECCLASS_PROCESS,
									PROCESS__TRANSITION,
									&audit);
		sepgsql_audit(rc, audit, NULL);
	}

	sepgsql_audit(rc, audit, NameStr(proc->proname));
	ReleaseSysCache(tup);
}

static void walkFuncExpr(Query *query, bool do_check, FuncExpr *func)
{
	Assert(IsA(func, FuncExpr));

	sepgsqlWalkExpr(query, do_check, (Node *) func->args);
	if (do_check)
		checkFunctionPerm(func->funcid);
}

static void walkAggref(Query *query, bool do_check, Aggref *aggref)
{
	Assert(IsA(aggref, Aggref));

	sepgsqlWalkExpr(query, do_check, (Node *) aggref->args);
	if (do_check)
		checkFunctionPerm(aggref->aggfnoid);
}

static void walkOpExpr(Query *query, bool do_check, OpExpr *expr)
{
	Assert(IsA(expr, OpExpr));
	sepgsqlWalkExpr(query, do_check, (Node *) expr->args);
}

static void walkBoolExpr(Query *query, bool do_check, BoolExpr *expr)
{
	Assert(IsA(expr, BoolExpr));
	sepgsqlWalkExpr(query, do_check, (Node *) expr->args);
}

static void walkCoerceToDomainExpr(Query *query, bool do_check, CoerceToDomain *expr)
{
	Assert(IsA(expr, CoerceToDomain));
	sepgsqlWalkExpr(query, do_check, (Node *) expr->arg);
}

static void walkList(Query *query, bool do_check, List *expr)
{
	ListCell *l;
	Assert(IsA(expr, List));
	foreach(l, expr)
		sepgsqlWalkExpr(query, do_check, (Node *) lfirst(l));
}

static void walkSortClause(Query *query, bool do_check, SortClause *sortcl)
{
	ListCell *l;

	Assert(IsA(sortcl, SortClause));
	foreach(l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		if (te->ressortgroupref == sortcl->tleSortGroupRef) {
			sepgsqlWalkExpr(query, do_check, (Node *) te->expr);
			break;
		}
	}
}

static void walkGroupClause(Query *query, bool do_check, GroupClause *gc)
{
	ListCell *l;

	Assert(IsA(gc, GroupClause));
	foreach(l, query->targetList) {
		TargetEntry *te = (TargetEntry *) lfirst(l);
		Assert(IsA(te, TargetEntry));
		if (te->ressortgroupref == gc->tleSortGroupRef) {
			sepgsqlWalkExpr(query, do_check, (Node *) te->expr);
			break;
		}
	}
}

void sepgsqlWalkExpr(Query *query, bool do_check, Node *n)
{
	if (n == NULL)
		return;

	switch (nodeTag(n)) {
	case T_Const:
		/* do nothing */
		break;
	case T_Var:
		walkVar(query, do_check, (Var *) n);
		break;
	case T_FuncExpr:
		walkFuncExpr(query, do_check, (FuncExpr *) n);
		break;
	case T_Aggref:
		walkAggref(query, do_check, (Aggref *) n);
		break;
	case T_OpExpr:
		walkOpExpr(query, do_check, (OpExpr *) n);
		break;
	case T_BoolExpr:
		walkBoolExpr(query, do_check, (BoolExpr *) n);
		break;
	case T_CoerceToDomain:
		walkCoerceToDomainExpr(query, do_check, (CoerceToDomain *) n);
		break;
	case T_List:
		walkList(query, do_check, (List *) n);
		break;
	case T_SortClause:
		walkSortClause(query, do_check, (SortClause *) n);
		break;
	case T_GroupClause:
		walkGroupClause(query, do_check, (GroupClause *) n);
		break;
	default:
		seldebug("expr(%d/%s) is not supported (do_check=%s)",
				 nodeTag(n), nodeToString(n), do_check ? "true" : "false");
		break;
	}
}
