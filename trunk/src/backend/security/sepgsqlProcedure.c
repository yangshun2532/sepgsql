/*
 * src/backend/security/sepgsqlProcedure.c
 *   SE-PostgreSQL hooks related to procedure
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "security/sepgsql.h"

/*
 * Trusted Procedure support
 */
static Datum sepgsqlExprStateEvalFunc(ExprState *expression,
									  ExprContext *econtext,
									  bool *isNull,
									  ExprDoneCond *isDone)
{
	Datum retval;
	psid saved_clientcon;

	/* save security context */
	saved_clientcon = sepgsqlGetClientPsid();
	sepgsqlSetClientPsid(expression->execContext);
	PG_TRY();
	{
		retval = expression->origEvalFunc(expression, econtext, isNull, isDone);
	}
	PG_CATCH();
	{
		sepgsqlSetClientPsid(saved_clientcon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	/* restore context */
	sepgsqlSetClientPsid(saved_clientcon);

	return retval;
}

void sepgsqlExecInitExpr(ExprState *state, PlanState *parent)
{
	switch (nodeTag(state->expr)) {
	case T_FuncExpr:
		{
			FuncExpr *func = (FuncExpr *) state->expr;
			HeapTuple tuple;
			psid execon;

			tuple = SearchSysCache(PROCOID, ObjectIdGetDatum(func->funcid), 0, 0, 0);
			if (!HeapTupleIsValid(tuple))
				selerror("RELOID cache lookup failed (pg_proc.oid=%u)", func->funcid);
			execon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   HeapTupleGetSecurity(tuple),
										   SECCLASS_PROCESS);
			if (sepgsqlGetClientPsid() != execon) {
				/* do domain transition */
				state->execContext = execon;
				state->origEvalFunc = state->evalfunc;
				state->evalfunc = sepgsqlExprStateEvalFunc;
			}
			ReleaseSysCache(tuple);
		}
		break;
	default:
		/* do nothing */
		break;
	}
}

/*
 * CREATE/DROP/ALTER FUNCTION statement
 */
void sepgsqlCreateProcedure(HeapTuple tuple)
{
	psid ncon;

	ncon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								 sepgsqlGetDatabasePsid(),
								 SECCLASS_PROCEDURE);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_PROCEDURE,
						   PROCEDURE__CREATE,
						   HeapTupleGetProcedureName(tuple));
}

void sepgsqlAlterProcedure(HeapTuple tuple, char *proselcon)
{
	psid ocon, ncon = InvalidOid;
	uint32 perms;

	ocon = HeapTupleGetSecurity(tuple);
	perms = DATABASE__SETATTR;
	if (proselcon) {
		Datum _ncon = DirectFunctionCall1(psid_in, CStringGetDatum(proselcon));
		ncon = DatumGetObjectId(_ncon);
		if (ocon != ncon)
			perms |= PROCEDURE__RELABELFROM;
	}

	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   ocon,
						   SECCLASS_PROCEDURE,
						   perms,
						   HeapTupleGetDatabaseName(tuple));
	if (ocon != ncon) {
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   ncon,
							   SECCLASS_PROCEDURE,
							   PROCEDURE__RELABELTO,
							   HeapTupleGetProcedureName(tuple));
		HeapTupleSetSecurity(tuple, ncon);
	}
}

void sepgsqlDropProcedure(HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_PROCEDURE,
						   PROCEDURE__DROP,
						   HeapTupleGetProcedureName(tuple));
}


