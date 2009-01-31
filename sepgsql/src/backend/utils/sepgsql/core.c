/*
 * src/backend/utils/sepgsql/core.c
 *    The core facility of SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/sepgsql.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

static security_context_t clientLabel = NULL;
static security_context_t serverLabel = NULL;
static security_context_t unlabeledLabel = NULL;

security_context_t
sepgsqlGetServerLabel(void)
{
	if (!serverLabel)
	{
		if (getcon_raw(&serverLabel) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not get server label")));
	}
	return serverLabel;
}

security_context_t
sepgsqlGetClientLabel(void)
{
	if (!clientLabel)
	{
		/*
		 * When the process is not invoked as a backend of client,
		 * it works as a server process and as a client process
		 * in same time.
		 */
		if (!MyProcPort)
			return sepgsqlGetServerLabel();

		/*
		 * SELinux provides getpeercon(3) which enables to obtain
		 * the security context of peer process.
		 * If MyProcPort->sock is unix domain socket, no special
		 * configuration is necessary. If it is tcp/ip socket,
		 * labeled IPsec or fallback context to be configured.
		 */
		if (getpeercon_raw(MyProcPort->sock, &clientLabel) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not obtain client label")));
	}

	return clientLabel;
}

security_context_t
sepgsqlSwitchClientLabel(security_context_t new_label)
{
	char *old_label = sepgsqlGetClientLabel();

	clientLabel = new_label;

	PG_TRY();
	{
		sepgsqlAvcSwitchClientLabel();
	}
	PG_CATCH();
	{
		clientLabel = old_label;
		PG_RE_THROW();
	}
	PG_END_TRY();

	return old_label;
}

security_context_t
sepgsqlGetUnlabeledLabel(void)
{
	if (!unlabeledLabel)
	{
		if (security_get_initial_context_raw("unlabeled",
											 &unlabeledLabel) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not get unlabeled label")));
	}
	return unlabeledLabel;
}

security_context_t
sepgsqlGetDatabaseLabel(void)
{
	security_context_t result;
	HeapTuple tuple;

	if (IsBootstrapProcessingMode())
	{
		static security_context_t dlabel = NULL;

		if (!dlabel)
		{
			security_class_t tclass
				= string_to_security_class("db_database");

			if (tclass == 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: db_database class is not installed")));

			if (security_compute_create_raw(sepgsqlGetClientLabel(),
											sepgsqlGetClientLabel(),
											tclass, &dlabel) < 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: could not get database label")));
		}
		return pstrdup(dlabel);
	}

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u", MyDatabaseId);

	result = sepgsqlLookupSecurityLabel(HeapTupleGetSecLabel(tuple));
	if (!result || !sepgsqlCheckValidSecurityLabel(result))
		result = sepgsqlGetUnlabeledLabel();

	ReleaseSysCache(tuple);

	return result;
}

Oid
sepgsqlGetDatabaseSid(void)
{
	HeapTuple tuple;
	Oid sid;

	if (IsBootstrapProcessingMode())
	{
		security_context_t dlabel
			= sepgsqlGetDatabaseLabel();

		return sepgsqlSecurityLabelToSid(dlabel);
	}

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u", MyDatabaseId);

	sid = HeapTupleGetSecLabel(tuple);

	ReleaseSysCache(tuple);

	return sid;
}

/*
 * sepgsqlIsEnabled()
 *
 *   returns the state of SE-PostgreSQL whether enabled, or not.
 *   When functions under src/backend/utils/ are invoked, they have to
 *   be checked on the head.
 *   This status is decided with two factors. The one is GUC parameter
 *   of "sepostgresql=on/off", and the other is is_selinux_enabled().
 *   Both of them have to be true, when SE-PostgreSQL is activated.
 */
bool sepostgresql_is_enabled;	/* default is false */

bool
sepgsqlIsEnabled(void)
{
	static int enabled = -1;	/* unchecked */

	if (!sepostgresql_is_enabled)
		return false;

	if (enabled < 0)
		enabled = is_selinux_enabled();

	return enabled > 0 ? true : false;
}

/*
 * sepgsqlInitialize
 */
void
sepgsqlInitialize(void)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsqlGetClientLabel();

	sepgsqlAvcInit();
}

/*
 * SE-PostgreSQL specific functions
 */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	return CStringGetTextDatum(sepgsqlGetClientLabel());
}

Datum
sepgsql_server_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	return CStringGetTextDatum(sepgsqlGetServerLabel());
}

Datum
sepgsql_database_getcon(PG_FUNCTION_ARGS)
{
	Name		dbname = PG_GETARG_NAME(0);
	Relation	rel;
	ScanKeyData	skey;
	SysScanDesc	scan;
	HeapTuple	tuple;
	Oid			sid;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	rel = heap_open(DatabaseRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				Anum_pg_database_datname,
				BTEqualStrategyNumber, F_NAMEEQ,
				NameGetDatum(dbname));

	scan = systable_beginscan(rel, DatabaseNameIndexId, true,
							  SnapshotNow, 1, &skey);

	tuple = systable_getnext(scan);

	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_DATABASE),
				 errmsg("SELinux: database \"%s\" not found",
						NameStr(*dbname))));

	sid = HeapTupleGetSecLabel(tuple);

	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	return CStringGetTextDatum(sepgsqlSidToSecurityLabel(sid));
}

Datum
sepgsql_table_getcon(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	Oid			sid;
	HeapTuple	tuple;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("SELinux: cache lookup failed for relation: %u", relid)));

	sid = HeapTupleGetSecLabel(tuple);

	ReleaseSysCache(tuple);

	return CStringGetTextDatum(sepgsqlSidToSecurityLabel(sid));
}

Datum
sepgsql_column_getcon(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	Name		attname = PG_GETARG_NAME(1);
	HeapTuple	tuple;
	Oid			sid;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("SELinux: disabled now")));

	tuple = SearchSysCache(ATTNAME,
						   ObjectIdGetDatum(relid),
						   CStringGetDatum(NameStr(*attname)),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
        ereport(ERROR,
                (errcode(ERRCODE_SELINUX_ERROR),
                 errmsg("SELinux: cache lookup failed "
						"for attribute: \"%s\", relation: %u",
						NameStr(*attname), relid)));

	sid = HeapTupleGetSecLabel(tuple);

	ReleaseSysCache(tuple);

	return CStringGetTextDatum(sepgsqlSidToSecurityLabel(sid));
}

Datum
sepgsql_procedure_getcon(PG_FUNCTION_ARGS)
{
	Oid			proid = PG_GETARG_OID(0);
	HeapTuple	tuple;
	Oid			sid;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	tuple =  SearchSysCache(PROCOID,
							ObjectIdGetDatum(proid),
							0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_FUNCTION),
				 errmsg("SELinux: cache lookup failed for procedure: %u", proid)));

	sid = HeapTupleGetSecLabel(tuple);

	ReleaseSysCache(tuple);

	return CStringGetTextDatum(sepgsqlSidToSecurityLabel(sid));
}
