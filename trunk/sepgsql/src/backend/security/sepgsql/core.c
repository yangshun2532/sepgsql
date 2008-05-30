/*
 * src/backend/security/sepgsqlCore.c
 *   SE-PostgreSQL core facilities like userspace AVC, policy state monitoring.
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "security/pgace.h"

/* sepgsql_getcon() -- returns a security context of client */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	PG_RETURN_OID(sepgsqlGetClientContext());
}

/* sepgsql_system_getcon() -- obtain the server's context */
static Oid sepgsql_system_getcon()
{
	security_context_t context;
	Oid ssid;

	if (getcon_raw(&context) != 0)
		elog(ERROR, "SELinux: could not obtain security context of server process");

	PG_TRY();
	{
		ssid = DatumGetObjectId(DirectFunctionCall1(security_label_raw_in,
													CStringGetDatum(context)));
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
	return ssid;
}

/* sepgsql_system_getpeercon() -- obtain the client's context */
static Oid sepgsql_system_getpeercon(int sockfd)
{
	security_context_t context, __context;
	Oid ssid;

	if (getpeercon_raw(sockfd, &context)) {
		/* we can set finally fallbacked context */
		__context = getenv("SEPGSQL_FALLBACK_CONTEXT");
		if (!__context)
			elog(ERROR, "SELinux: could not obtain security context of database client");
		if (security_check_context(__context) ||
			selinux_trans_to_raw_context(__context, &context))
			elog(ERROR, "SELinux: '%s' is not a valid context", __context);
	}

	PG_TRY();
	{
		ssid = DatumGetObjectId(DirectFunctionCall1(security_label_raw_in,
													CStringGetDatum(context)));
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
	return ssid;
}

static Oid sepgsqlServerContext = InvalidOid;
static Oid sepgsqlClientContext = InvalidOid;

Oid sepgsqlGetServerContext()
{
	return sepgsqlServerContext;
}

Oid sepgsqlGetClientContext()
{
	return sepgsqlClientContext;
}

void sepgsqlSetClientContext(Oid new_context)
{
	sepgsqlClientContext = new_context;
}

Oid sepgsqlGetDefaultDatabaseContext(void)
{
	static Oid default_dbcon_cached = InvalidOid;
	char *context, *user, *role, *type, *range;
	char buffer[1024];

	if (default_dbcon_cached != InvalidOid)
		return default_dbcon_cached;

	/*
	 * TODO: we should call selabel_lookup() here, when libselinux
	 *       got SE-PostgreSQL default database context support.
	 */
	context = DatumGetCString(DirectFunctionCall1(security_label_raw_out,
								 ObjectIdGetDatum(sepgsqlGetClientContext())));
	user = strtok(context, ":");
	role = strtok(NULL, ":");
	type = strtok(NULL, ":");
	range = strtok(NULL, "-");
	snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
			 user, "object_r", "sepgsql_db_t", range);
	default_dbcon_cached =
		DatumGetObjectId(DirectFunctionCall1(security_label_raw_in,
											 CStringGetDatum(buffer)));

	return default_dbcon_cached;
}

Oid sepgsqlGetDatabaseContext()
{
	HeapTuple tuple;
	Oid datcon;

	if (IsBootstrapProcessingMode())
		return sepgsqlGetDefaultDatabaseContext();

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u", MyDatabaseId);
	datcon = HeapTupleGetSecurity(tuple);
	ReleaseSysCache(tuple);

	return datcon;
}

char *sepgsqlGetDatabaseName()
{
	Form_pg_database dat_form;
	HeapTuple tuple;
	char *datname;

	if (IsBootstrapProcessingMode())
		return NULL;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u", MyDatabaseId);
	dat_form = (Form_pg_database) GETSTRUCT(tuple);
	datname = pstrdup(NameStr(dat_form->datname));
	ReleaseSysCache(tuple);

	return datname;
}

void sepgsqlInitialize(bool is_bootstrap)
{
	sepgsql_avc_init();

	/* obtain security context of server process */
	sepgsqlServerContext = sepgsql_system_getcon();

	if (IsBootstrapProcessingMode()) {
		sepgsqlClientContext = sepgsqlServerContext;
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   sepgsqlGetDatabaseContext(),
							   SECCLASS_DB_DATABASE,
							   DB_DATABASE__ACCESS,
							   NULL);
		return;
	}

	/* obtain security context of client process */
	if (MyProcPort != NULL)
		sepgsqlClientContext = sepgsql_system_getpeercon(MyProcPort->sock);
	else
		sepgsqlClientContext = sepgsql_system_getcon();

	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   sepgsqlGetDatabaseContext(),
						   SECCLASS_DB_DATABASE,
						   DB_DATABASE__ACCESS,
						   sepgsqlGetDatabaseName());
}

bool sepgsqlIsEnabled()
{
	static int enabled = -1;

	if (enabled < 0)
		enabled = is_selinux_enabled();

	return enabled > 0 ? true : false;
}
