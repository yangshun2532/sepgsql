/*
 * src/backend/selinux/create_database.c
 *    CREATE DATABASE statement support
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "sepgsql.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

void sepgsqlCreateDatabase(Datum *values, char *nulls)
{
	psid db_psid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetServerPsid(),
										 SECCLASS_DATABASE);
	values[Anum_pg_database_datselcon - 1] = ObjectIdGetDatum(db_psid);
	nulls[Anum_pg_database_datselcon - 1] = ' ';
}

void sepgsqlDropDatabase(Form_pg_database pgdat)
{
	char *audit;
	int rc;

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								pgdat->datselcon,
								SECCLASS_DATABASE,
								DATABASE__DROP,
								&audit);
	sepgsql_audit(rc, audit, NameStr(pgdat->datname));
}

void sepgsqlAlterDatabase(Form_pg_database pgdat)
{
	char *audit;
	int rc;

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								pgdat->datselcon,
								SECCLASS_DATABASE,
								DATABASE__SETATTR,
								&audit);
	sepgsql_audit(rc, audit, NameStr(pgdat->datname));
}

psid sepgsqlAlterDatabaseContext(Form_pg_database pgdat, char *newcon)
{
	psid newpsid;
	char *audit;
	int rc;

	newpsid = DatumGetObjectId(DirectFunctionCall1(psid_in, CStringGetDatum(newcon)));

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								pgdat->datselcon,
								SECCLASS_DATABASE,
								DATABASE__SETATTR | DATABASE__RELABELFROM,
								&audit);
	sepgsql_audit(rc, audit, NameStr(pgdat->datname));

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								newpsid,
								SECCLASS_DATABASE,
								DATABASE__RELABELTO,
								&audit);
	sepgsql_audit(rc, audit, NameStr(pgdat->datname));

	return newpsid;
}
