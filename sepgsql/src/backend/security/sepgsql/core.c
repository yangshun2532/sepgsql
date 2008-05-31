/*
 * src/backend/security/sepgsqlCore.c
 *   SE-PostgreSQL core facilities like userspace AVC, policy state monitoring.
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_security.h"
#include "libpq/libpq.h"
#include "miscadmin.h"
#include "security/pgace.h"
#include "utils/syscache.h"

static security_context_t serverContext = NULL;
static security_context_t clientContext = NULL;
static security_context_t databaseContext = NULL;

const security_context_t sepgsqlGetServerContext(void)
{
	Assert(serverContext != NULL);
	return serverContext;
}

const security_context_t sepgsqlGetClientContext(void)
{
	Assert(clientContext != NULL);
	return clientContext;
}

const security_context_t sepgsqlGetDatabaseContext(void)
{
	Assert(databaseContext != NULL);
	return databaseContext;
}

const security_context_t sepgsqlGetDefaultDatabaseContext(void)
{
	static security_context_t defaultDatabaseContext = NULL;
	security_context_t context;
	char *user, *role, *type, *range;
	char buffer[1024];

	if (defaultDatabaseContext)
		return defaultDatabaseContext;

	/*
	 * TODO: we should call selabel_lookup() here, when libselinux got
	 *       default database context support.
	 */
	context = pstrdup(sepgsqlGetClientContext());

	user = strtok(context, ":");
	role = strtok(NULL, ":");
	type = strtok(NULL, ":");
	range = strtok(NULL, "-");

	snprintf(buffer, sizeof(buffer), "%s:object_r:%s:%s",
			 user, "sepgsql_db_t", range);
	if (security_check_context_raw((security_context_t) buffer))
		elog(ERROR, "SELinux: invalid default database context");

	defaultDatabaseContext = strdup(buffer);
	if (!defaultDatabaseContext)
		elog(ERROR, "SELinux: memory allocation error");

	return defaultDatabaseContext;
}

const security_context_t sepgsqlSwitchClientContext(security_context_t new_context)
{
	security_context_t original_context = clientContext;

	clientContext = new_context;

	return original_context;
}

static void initContexts(void)
{
	/* server context */
	if (getcon_raw(&serverContext))
		elog(ERROR, "SELinux: could not get security context of server process");

	/* client context */
	if (!MyProcPort)
	{
		/* a client process is a server process in same time */
		clientContext = serverContext;
	}
	else
	{
		if (getpeercon_raw(MyProcPort->sock, &clientContext))
		{
			/* fallbacked security context */
			char *fallback = getenv("SEPGSQL_FALLBACK_CONTEXT");

			if (!fallback)
				elog(ERROR, "SELinux: could not get security context of client process");
			if (security_check_context(fallback)
				|| selinux_trans_to_raw_context(fallback, &clientContext))
				elog(ERROR, "SELinux: %s is not a valid security context", fallback);
		}
	}

	/* database context */
	if (IsBootstrapProcessingMode())
	{
		databaseContext = sepgsqlGetDefaultDatabaseContext();
	}
	else
	{
		HeapTuple tuple;
		Oid security_id;
		Datum labelTxt;
		bool isnull;

		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(MyDatabaseId),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for database %u", MyDatabaseId);
		security_id = HeapTupleGetSecurity(tuple);
		ReleaseSysCache(tuple);

		tuple = SearchSysCache(SECURITYOID,
							   ObjectIdGetDatum(security_id),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for security id %u", security_id);
		labelTxt = SysCacheGetAttr(SECURITYOID,
								   tuple,
								   Anum_pg_security_seclabel,
								   &isnull);
		Assert(isnull != false);

		databaseContext = strdup(TextDatumGetCString(labelTxt));
		if (!databaseContext)
			elog(ERROR, "SELinux: memory allocation error");
	}
}

void sepgsqlInitialize(bool bootstrap)
{
	char *dbname;

	sepgsqlAvcInit();

	initContexts();

	/* check db_database:{ access } */
	if (IsBootstrapProcessingMode())
		dbname = "template1";
	else
	{
		Form_pg_database dbForm;
		HeapTuple tuple;

		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(MyDatabaseId),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for database %u", MyDatabaseId);
		dbForm = (Form_pg_database) GETSTRUCT(tuple);

		dbname = pstrdup(NameStr(dbForm->datname));

		ReleaseSysCache(tuple);
	}

	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 sepgsqlGetDatabaseContext(),
						 SECCLASS_DB_DATABASE,
						 DB_DATABASE__ACCESS,
						 dbname);
}

bool sepgsqlIsEnabled(void)
{
	static int enabled = -1;

	if (enabled < 0)
		enabled = is_selinux_enabled();

	return enabled > 0 ? true : false;
}

/*
 * sepgsql_getcon(void) -- returns a security context of client
 */
Datum sepgsql_getcon(PG_FUNCTION_ARGS)
{
	security_context_t context;
	Datum labelTxt;

	if (selinux_raw_to_trans_context(clientContext, &context))
		elog(ERROR, "SELinux: could not translate mls label");
	PG_TRY();
	{
		labelTxt = CStringGetTextDatum(context);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);

	return labelTxt;
}

#if 0
Datum sepgsql_get_user(PG_FUNCTION_ARGS)
{}

Datum sepgsql_set_user(PG_FUNCTION_ARGS)
{}

Datum sepgsql_get_role(PG_FUNCTION_ARGS)
{}

Datum sepgsql_set_role(PG_FUNCTION_ARGS)
{}

Datum sepgsql_get_type(PG_FUNCTION_ARGS)
{}

Datum sepgsql_set_type(PG_FUNCTION_ARGS)
{}

Datum sepgsql_get_range(PG_FUNCTION_ARGS)
{}

Datum sepgsql_set_range(PG_FUNCTION_ARGS)
{}
#endif
