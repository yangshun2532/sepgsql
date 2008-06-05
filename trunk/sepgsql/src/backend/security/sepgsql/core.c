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
#include <selinux/context.h>

static security_context_t serverContext = NULL;
static security_context_t clientContext = NULL;
static security_context_t databaseContext = NULL;
static security_context_t unlabeledContext = NULL;

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

const security_context_t sepgsqlGetUnlabeledContext(void)
{
	if (unlabeledContext)
		return unlabeledContext;

	if (security_get_initial_context_raw("unlabeled", &unlabeledContext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get unlabeled context")));

	return unlabeledContext;
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
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get server process context")));

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
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: could not get client process context")));

			if (security_check_context(fallback)
				|| selinux_trans_to_raw_context(fallback, &clientContext))
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: %s is not a valid context", fallback)));
		}
	}

	/* database context */
	if (IsBootstrapProcessingMode())
	{
		if (security_compute_create_raw(clientContext,
										clientContext,
										SECCLASS_DB_DATABASE,
										&databaseContext) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not get database context")));
	}
	else
	{
		HeapTuple tuple;
		security_context_t dbcontext;

		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(MyDatabaseId),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for database %u", MyDatabaseId);
		dbcontext = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));
		databaseContext = strdup(dbcontext);
		ReleaseSysCache(tuple);
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
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
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

	PG_RETURN_DATUM(labelTxt);
}

Datum sepgsql_getservcon(PG_FUNCTION_ARGS)
{
	security_context_t context;
	Datum labelTxt;

	if (selinux_raw_to_trans_context(serverContext, &context))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
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

	PG_RETURN_DATUM(labelTxt);
}

static void parse_to_context(security_context_t context,
							 char **user, char **role, char **type, char **range)
{
	security_context_t raw_context;

	if (selinux_trans_to_raw_context(context, &raw_context) < 0)
        ereport(ERROR,
                (errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
	PG_TRY();
	{
		char *tmp;

		tmp = pstrdup(strtok(raw_context, ":"));
		if (user)
			*user = tmp;
		tmp = pstrdup(strtok(NULL, ":"));
		if (role)
			*role = tmp;
		tmp = pstrdup(strtok(NULL, ":"));
		if (type)
			*type = tmp;
		if (is_selinux_mls_enabled())
		{
			tmp = pstrdup(strtok(NULL, "\0"));
			if (range)
				*range = tmp;
		}
		else if (range)
			*range = NULL;
	}
	PG_CATCH();
	{
		freecon(raw_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
    freecon(raw_context);
}

Datum sepgsql_get_user(PG_FUNCTION_ARGS)
{
	char *user;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 &user, NULL, NULL, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(user));
}

Datum sepgsql_set_user(PG_FUNCTION_ARGS)
{
	char *user, *role, *type, *range;
	char buffer[1024];
	security_context_t newcon;
	Datum result;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 &user, &role, &type, &range);
	if (range)
		snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
				 TextDatumGetCString(PG_GETARG_TEXT_P(1)), role, type, range);
	else
		snprintf(buffer, sizeof(buffer), "%s:%s:%s",
				 TextDatumGetCString(PG_GETARG_TEXT_P(1)), role, type);
	if (selinux_raw_to_trans_context((security_context_t) buffer, &newcon) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not set a new user")));
	PG_TRY();
    {
		result = CStringGetTextDatum(newcon);
	}
    PG_CATCH();
    {
		freecon(newcon);
        PG_RE_THROW();
    }
    PG_END_TRY();
	freecon(newcon);

	PG_RETURN_DATUM(result);
}

Datum sepgsql_get_role(PG_FUNCTION_ARGS)
{
	char *role;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 NULL, &role, NULL, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(role));
}

Datum sepgsql_set_role(PG_FUNCTION_ARGS)
{
	char *user, *role, *type, *range;
	char buffer[1024];
	security_context_t newcon;
	Datum result;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 &user, &role, &type, &range);
	if (range)
		snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
				 user, TextDatumGetCString(PG_GETARG_TEXT_P(1)), type, range);
	else
		snprintf(buffer, sizeof(buffer), "%s:%s:%s",
				 user, TextDatumGetCString(PG_GETARG_TEXT_P(1)), type);
	if (selinux_raw_to_trans_context((security_context_t) buffer, &newcon) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not set a new role")));
	PG_TRY();
    {
		result = CStringGetTextDatum(newcon);
	}
    PG_CATCH();
    {
		freecon(newcon);
        PG_RE_THROW();
    }
    PG_END_TRY();
	freecon(newcon);

	PG_RETURN_DATUM(result);
}

Datum sepgsql_get_type(PG_FUNCTION_ARGS)
{
	char *type;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 NULL, NULL, &type, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(type));
}

Datum sepgsql_set_type(PG_FUNCTION_ARGS)
{
	char *user, *role, *type, *range;
	char buffer[1024];
	security_context_t newcon;
	Datum result;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 &user, &role, &type, &range);
	if (range)
		snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
				 user, role, TextDatumGetCString(PG_GETARG_TEXT_P(1)), range);
	else
		snprintf(buffer, sizeof(buffer), "%s:%s:%s",
				 user, role, TextDatumGetCString(PG_GETARG_TEXT_P(1)));
	if (selinux_raw_to_trans_context((security_context_t) buffer, &newcon) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not set a new type")));
	PG_TRY();
    {
		result = CStringGetTextDatum(newcon);
	}
    PG_CATCH();
    {
		freecon(newcon);
        PG_RE_THROW();
    }
    PG_END_TRY();
	freecon(newcon);

	PG_RETURN_DATUM(result);
}

Datum sepgsql_get_range(PG_FUNCTION_ARGS)
{
	char *range;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 NULL, NULL, NULL, &range);
	PG_RETURN_TEXT_P(CStringGetTextDatum(range));
}

Datum sepgsql_set_range(PG_FUNCTION_ARGS)
{
	char *user, *role, *type, *range;
	char buffer[1024];
	security_context_t newcon;
	Datum result;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 &user, &role, &type, &range);
	if (range)
		snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
				 user, role, type,TextDatumGetCString(PG_GETARG_TEXT_P(1)));
	else
		snprintf(buffer, sizeof(buffer), "%s:%s:%s",
				 user, role, type);
	if (selinux_raw_to_trans_context((security_context_t) buffer, &newcon) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not set a new range")));
	PG_TRY();
    {
		result = CStringGetTextDatum(newcon);
	}
    PG_CATCH();
    {
		freecon(newcon);
        PG_RE_THROW();
    }
    PG_END_TRY();
	freecon(newcon);

	PG_RETURN_DATUM(result);
}
