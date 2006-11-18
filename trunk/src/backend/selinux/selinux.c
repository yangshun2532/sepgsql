/*
 * src/backend/selinux/selinux.c
 *    SE-PgSQL bootstrap hook functions.
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/htup.h"
#include "catalog/pg_database.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "sepgsql.h"
#include "utils/syscache.h"
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static psid selinuxServerPsid = InvalidOid;
static psid selinuxClientPsid = InvalidOid;
static psid selinuxDatabasePsid = InvalidOid;

psid selinuxGetServerPsid()
{
	return selinuxServerPsid;
}

psid selinuxGetClientPsid()
{
	return selinuxClientPsid;
}

psid selinuxGetDatabasePsid()
{
	return selinuxDatabasePsid;
}

void selinuxInitialize()
{
	libselinux_avc_reset();

	if (IsBootstrapProcessingMode()) {
		selinuxServerPsid = libselinux_getcon();
		selinuxClientPsid = libselinux_getcon();
		selinuxDatabasePsid = libselinux_avc_createcon(selinuxClientPsid,
													   selinuxServerPsid,
													   SECCLASS_DATABASE);
		return;
	}

	/* obtain security context of server process */
	selinuxServerPsid = libselinux_getcon();

	/* obtain security context of client process */
	if (MyProcPort != NULL) {
		selinuxClientPsid = libselinux_getpeercon(MyProcPort->sock);
	} else {
		selinuxClientPsid = libselinux_getcon();
	}

	/* obtain security context of database */
	if (MyDatabaseId == TemplateDbOid) {
		selinuxDatabasePsid = libselinux_avc_createcon(selinuxClientPsid,
													   selinuxServerPsid,
													   SECCLASS_DATABASE);
	} else {
		HeapTuple tuple;
		Form_pg_database pg_database;
		
		tuple = SearchSysCache(DATABASEOID, ObjectIdGetDatum(MyDatabaseId), 0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("could not obtain security context of database");
		pg_database = (Form_pg_database) GETSTRUCT(tuple);
		selinuxDatabasePsid = pg_database->datselcon;
		ReleaseSysCache(tuple);
	}
}
