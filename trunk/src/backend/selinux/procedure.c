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
	selinux_audit(rc, audit, NULL);

	/* 2. check procedure:create permission */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								ppsid, SECCLASS_PROCEDURE,
								PROCEDURE__CREATE, &audit);
	selinux_audit(rc, audit, NULL);

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
	selinux_audit(rc, audit, NameStr(pg_proc->proname));

	/* 3. check procedure:relabelto, if necessary */
	if (nsid != InvalidOid) {
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), nsid,
									SECCLASS_PROCEDURE,
									PROCEDURE__RELABELTO, &audit);
		selinux_audit(rc, audit, NameStr(pg_proc->proname));
		pg_proc->proselcon = nsid;
	}
}

psid sepgsqlPrepareProcedure(Oid funcid)
{
	HeapTuple tuple;
	psid orig_psid, new_psid;

   	tuple = SearchSysCache(PROCOID, ObjectIdGetDatum(funcid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("could not lookup the procedure (funcid=%u)", funcid);
	new_psid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 ((Form_pg_proc) GETSTRUCT(tuple))->proselcon,
									 SECCLASS_PROCESS);
	ReleaseSysCache(tuple);

	orig_psid = sepgsqlGetClientPsid();
	sepgsqlSetClientPsid(new_psid);

	return orig_psid;
}

void sepgsqlRestoreProcedure(psid orig_psid)
{
	sepgsqlSetClientPsid(orig_psid);
}
