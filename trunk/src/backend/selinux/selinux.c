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

/* ------------------------------------------------
 * SQL functions in Security Enhanced PostgreSQL
 * ------------------------------------------------ */

/* selinux_getcon() -- returns a security context of client
 * process.
 */
Datum
selinux_getcon(PG_FUNCTION_ARGS)
{
	PG_RETURN_OID(selinuxGetClientPsid());
}

/* selinux_permission()/selinux_permission_noaudit()
 * checks permissions based on security policy between ssid,
 * tsid and tclass.
 * In selinux_permission(), it may print an audit message if generated,
 * @ssid : security context of subject
 * @tsid : security context of object
 * @tclass : object class
 * @perms : permission set
 */
Datum
selinux_permission(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid tsid = PG_GETARG_OID(1);
	uint16 tclass = PG_GETARG_UINT32(2);
	uint32 perms = PG_GETARG_UINT32(3);
	int rc;
	char *audit;

	rc = libselinux_avc_permission(ssid, tsid, tclass, perms, &audit);
	if (audit)
		selnotice(audit);
	PG_RETURN_BOOL(rc == 0);
}

Datum
selinux_permission_noaudit(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid tsid = PG_GETARG_OID(1);
	uint16 tclass = PG_GETARG_UINT32(2);
	uint32 perms = PG_GETARG_UINT32(3);
	int rc;

	rc = libselinux_avc_permission(ssid, tsid, tclass, perms, NULL);
	PG_RETURN_BOOL(rc == 0);
}

/* selinux_sql_check_context_insert() -- abort transaction
 * if subject didn't have a permission to insert a new tuple
 * into a table.
 * @ssid : security context of subject
 * @isid : security context automatically computed
 * @esid : security context which to be applied
 * @tclass : object class
 */
Datum
selinux_check_context_insert(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid isid = PG_GETARG_OID(1);
	psid esid = PG_GETARG_OID(2);
	uint16 tclass = PG_GETARG_INT32(3);
	char *audit;
	uint32 perms;
	int rc;

	if (tclass == SECCLASS_TUPLE) {
		perms = TUPLE__INSERT;
		if (isid != esid)
			perms |= TUPLE__RELABELFROM;
	} else {
		perms = COMMON_DATABASE__SETATTR;
		if (isid != esid)
			perms |= COMMON_DATABASE__RELABELFROM;
	}

	rc = libselinux_avc_permission(ssid, isid, tclass, perms, &audit);
	selinux_audit(rc, audit);

	if (isid != esid) {
		perms = (tclass == SECCLASS_TUPLE) ? TUPLE__RELABELTO : COMMON_DATABASE__RELABELTO;
		rc = libselinux_avc_permission(ssid, esid, tclass, perms, &audit);
		selinux_audit(rc, audit);
	}
	PG_RETURN_OID(esid);
}

/* selinux_check_context_update() -- abort transaction
 * if subject didn't have a permission to relabel the old
 * security context to the new one.
 * @ssid : security context of subject
 * @osid : old security context of object
 * @nsid : new security context of object
 * @tclass : object class
 */
Datum
selinux_check_context_update(PG_FUNCTION_ARGS)
{
	psid ssid = PG_GETARG_OID(0);
	psid osid = PG_GETARG_OID(1);
	psid nsid = PG_GETARG_OID(2);
	uint16 tclass = PG_GETARG_INT32(3);
	char *audit;
	uint32 perms;
	int rc;

	if (tclass == SECCLASS_TUPLE) {
		perms = TUPLE__UPDATE;
		if (osid != nsid)
			perms |= TUPLE__RELABELFROM;
	} else {
		perms = COMMON_DATABASE__SETATTR;
		if (osid != nsid)
			perms |= COMMON_DATABASE__RELABELFROM;
	}
	
	rc = libselinux_avc_permission(ssid, osid, tclass, perms, &audit);
	selinux_audit(rc, audit);
	
	if (osid != nsid) {
		perms = (tclass == SECCLASS_TUPLE) ? TUPLE__RELABELTO : COMMON_DATABASE__RELABELTO;
		rc = libselinux_avc_permission(ssid, nsid, tclass, perms, &audit);
		selinux_audit(rc, audit);
	}
	PG_RETURN_OID(nsid);
}
