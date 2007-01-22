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
		sepgsqlWalkExpr(query, do_check, (Expr *)var);
		break;
	default:
		seldebug("rtekind = %u is ignored", rte->rtekind);
		break;
	}
}

static void walkFuncExpr(Query *query, bool do_check, FuncExpr *func)
{
	ListCell *l;
	Assert(IsA(func, FuncExpr));

	foreach(l, func->args)
		sepgsqlWalkExpr(query, do_check, (Expr *) lfirst(l));

	if (do_check) {
		Form_pg_proc proc;
		HeapTuple tup;
		psid newcon;
		uint32 perms;
		char *audit;
		int rc;

		tup = SearchSysCache(PROCOID,
							 ObjectIdGetDatum(func->funcid),
							 0, 0, 0);
		if (!HeapTupleIsValid(tup))
			selerror("cache lookup failed (procid=%u)", func->funcid);
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
}

static void walkOpExpr(Query *query, bool do_check, OpExpr *expr)
{
	ListCell *l;
	Assert(IsA(expr, OpExpr));
	foreach(l, expr->args)
		sepgsqlWalkExpr(query, do_check, (Expr *) lfirst(l));
}

static void walkBoolExpr(Query *query, bool do_check, BoolExpr *expr)
{
	ListCell *l;
	Assert(IsA(expr, BoolExpr));
	foreach(l, expr->args)
		sepgsqlWalkExpr(query, do_check, (Expr *) lfirst(l));
}

static void walkCoerceToDomainExpr(Query *query, bool do_check, CoerceToDomain *expr)
{
	Assert(IsA(expr, CoerceToDomain));
	sepgsqlWalkExpr(query, do_check, expr->arg);
}

static void walkList(Query *query, bool do_check, List *expr)
{
	ListCell *l;
	Assert(IsA(expr, List));
	foreach(l, expr)
		sepgsqlWalkExpr(query, do_check, (Expr *) lfirst(l));
}

void sepgsqlWalkExpr(Query *query, bool do_check, Expr *expr)
{
	if (expr == NULL)
		return;

	switch (nodeTag(expr)) {
	case T_Const:
		/* do nothing */
		break;
	case T_Var:
		walkVar(query, do_check, (Var *)expr);
		break;
	case T_FuncExpr:
		walkFuncExpr(query, do_check, (FuncExpr *)expr);
		break;
	case T_OpExpr:
		walkOpExpr(query, do_check, (OpExpr *)expr);
		break;
	case T_BoolExpr:
		walkBoolExpr(query, do_check, (BoolExpr *)expr);
		break;
	case T_CoerceToDomain:
		walkCoerceToDomainExpr(query, do_check, (CoerceToDomain *)expr);
		break;
	case T_List:
		walkList(query, do_check, (List *) expr);
		break;
	default:
		seldebug("expr(%d/%s) is not supported (do_check=%s)", nodeTag(expr), nodeToString((Node *)expr), do_check ? "true" : "false");
		break;
	}
}
