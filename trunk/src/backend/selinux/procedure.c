/*
 * src/backend/selinux/procedure.c
 *    The procedure supportings for SE-PostgreSQL
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "sepgsql.h"

#include <catalog/pg_proc.h>
#include <fmgr.h>
#include <miscadmin.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <utils/syscache.h>

Query *selinuxProxyCreateProcedure(Query *query)
{
	psid ppsid;
	int rc;
	char *audit;

	/* compute the context of newly created procedure */
	ppsid = libselinux_avc_createcon(selinuxGetClientPsid(),
									 selinuxGetDatabasePsid(),
									 SECCLASS_PROCEDURE);

	/* 1. check database:create_obj permission */
	rc = libselinux_avc_permission(selinuxGetClientPsid(),
								   selinuxGetDatabasePsid(),
								   SECCLASS_DATABASE,
								   DATABASE__CREATE_OBJ, &audit);
	selinux_audit(rc, audit, NULL);

	/* 2. check procedure:create permission */
	rc = libselinux_avc_permission(selinuxGetClientPsid(),
								   ppsid, SECCLASS_PROCEDURE,
								   PROCEDURE__CREATE, &audit);
	selinux_audit(rc, audit, NULL);

	return query;
}

void selinuxHookCreateProcedure(Datum *values, char *nulls)
{
	psid ppsid = libselinux_avc_createcon(selinuxGetClientPsid(),
										  selinuxGetDatabasePsid(),
										  SECCLASS_PROCEDURE);
	values[Anum_pg_proc_proselcon - 1] = ObjectIdGetDatum(ppsid);
	nulls[Anum_pg_proc_proselcon - 1] = ' ';
}

psid selinuxHookPrepareProcedure(Oid funcid)
{
	HeapTuple tuple;
	Form_pg_proc pg_proc;
	psid orig_psid, new_psid;

   	tuple = SearchSysCache(PROCOID, ObjectIdGetDatum(funcid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("could not lookup the procedure (funcid=%u)", funcid);
	new_psid = libselinux_avc_createcon(selinuxGetClientPsid(),
										((Form_pg_proc) GETSTRUCT(tuple))->proselcon,
										SECCLASS_PROCESS);
	ReleaseSysCache(tuple);

	orig_psid = selinuxGetClientPsid();
	selinuxSetClientPsid(new_psid);

	return orig_psid;
}

void selinuxHookRestoreProcedure(psid orig_psid)
{
	selinuxSetClientPsid(orig_psid);
}
