/*
 * src/backend/selinux/procedure.c
 *    The procedure supportings for SE-PostgreSQL
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "nodes/execnodes.h"
#include "nodes/parsenodes.h"
#include "sepgsql.h"
#include "utils/syscache.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

Query *sepgsqlProxyCreateProcedure(Query *query)
{
	psid ppsid;
	int rc;
	char *audit;

	/* compute the context of newly created procedure */
	ppsid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								  sepgsqlGetDatabasePsid(),
								  SECCLASS_PROCEDURE);

	/* 1. check database:create_obj permission */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								sepgsqlGetDatabasePsid(),
								SECCLASS_DATABASE,
								DATABASE__CREATE_OBJ, &audit);
	sepgsql_audit(rc, audit, NULL);

	/* 2. check procedure:create permission */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								ppsid, SECCLASS_PROCEDURE,
								PROCEDURE__CREATE, &audit);
	sepgsql_audit(rc, audit, NULL);

	return query;
}

void sepgsqlCreateProcedure(Datum *values, char *nulls)
{
	psid ppsid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									   sepgsqlGetDatabasePsid(),
									   SECCLASS_PROCEDURE);
	values[Anum_pg_proc_proselcon - 1] = ObjectIdGetDatum(ppsid);
	nulls[Anum_pg_proc_proselcon - 1] = ' ';
}

void sepgsqlAlterProcedure(Form_pg_proc pg_proc, AlterFunctionStmt *stmt)
{
	ListCell *l;
	psid nsid = InvalidOid;
	uint32 perms = PROCEDURE__SETATTR;
	char *audit;
	int rc;

	/* 1. check whether 'ALTER FUNCTION' contains context = '...' */
retry:
	foreach(l, stmt->actions) {
		DefElem *defel = (DefElem *) lfirst(l);

		if (strcmp(defel->defname, "context") == 0) {
			perms |= PROCEDURE__RELABELFROM;
			nsid = DatumGetObjectId(DirectFunctionCall1(psid_in,
														CStringGetDatum(strVal(defel->arg))));
			stmt->actions = list_delete(stmt->actions, defel);
			goto retry;
		}
	}

	/* 2. check procedure:{setattr relabelfrom} */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								pg_proc->proselcon,
								SECCLASS_PROCEDURE,
								perms, &audit);
	sepgsql_audit(rc, audit, NameStr(pg_proc->proname));

	/* 3. check procedure:relabelto, if necessary */
	if (nsid != InvalidOid) {
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), nsid,
									SECCLASS_PROCEDURE,
									PROCEDURE__RELABELTO, &audit);
		sepgsql_audit(rc, audit, NameStr(pg_proc->proname));
		pg_proc->proselcon = nsid;
	}
}

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
			Form_pg_proc pg_proc;
			HeapTuple tuple;
			psid execon;

			tuple = SearchSysCache(PROCOID, ObjectIdGetDatum(func->funcid), 0, 0, 0);
			if (!HeapTupleIsValid(tuple))
				selerror("RELOID cache lookup failed (pg_proc.oid=%u)", func->funcid);
			pg_proc = (Form_pg_proc) GETSTRUCT(tuple);
			execon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   pg_proc->proselcon,
										   SECCLASS_PROCESS);
			if (sepgsqlGetClientPsid() != execon) {
				/* do domain transition */
				state->execContext = execon;
				state->origEvalFunc = state->evalfunc;
				state->evalfunc = sepgsqlExprStateEvalFunc;
				strcpy(NameStr(state->proname), NameStr(pg_proc->proname));
			}
			ReleaseSysCache(tuple);
		}
		break;
	default:
		/* do nothing */
		break;
	}
}
