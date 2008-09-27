
/*
 * src/backend/security/sepgsqlCore.c
 *	 SE-PostgreSQL core facilities
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
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
static security_context_t unlabeledContext = NULL;

const security_context_t
sepgsqlGetServerContext(void)
{
	Assert(serverContext != NULL);
	return serverContext;
}

const security_context_t
sepgsqlGetClientContext(void)
{
	Assert(clientContext != NULL);
	return clientContext;
}

const security_context_t
sepgsqlGetDatabaseContext(void)
{
	security_context_t dcontext;

	if (IsBootstrapProcessingMode())
	{
		security_context_t tmp;

        if (security_compute_create_raw(sepgsqlGetClientContext(),
										sepgsqlGetClientContext(),
										SECCLASS_DB_DATABASE, &tmp) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not get database context")));
        PG_TRY();
        {
			dcontext = pstrdup(tmp);
        }
        PG_CATCH();
        {
			freecon(tmp);
			PG_RE_THROW();
        }
        PG_END_TRY();
        freecon(tmp);
	}
	else
	{
		HeapTuple tuple;

		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(MyDatabaseId),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for database: %u", MyDatabaseId);

		dcontext = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));

		ReleaseSysCache(tuple);
	}

	return dcontext;
}

Oid
sepgsqlGetDatabaseSecurityId(void)
{
	Oid security_id;

	if (IsBootstrapProcessingMode())
	{
		security_context_t dcontext
			= sepgsqlGetDatabaseContext();

		security_id = pgaceSecurityLabelToSid(dcontext);
	}
	else
	{
		HeapTuple tuple;

		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(MyDatabaseId),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for database: %u", MyDatabaseId);

		security_id = HeapTupleGetSecurity(tuple);

		ReleaseSysCache(tuple);
	}

	return security_id;
}

const security_context_t
sepgsqlGetUnlabeledContext(void)
{
	if (unlabeledContext)
		return unlabeledContext;

	if (security_get_initial_context_raw("unlabeled", &unlabeledContext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get unlabeled context")));

	return unlabeledContext;
}

const security_context_t
sepgsqlSwitchClientContext(security_context_t new_context)
{
	security_context_t original_context = clientContext;

	clientContext = new_context;

	return original_context;
}

static void
initContexts(void)
{
	/*
	 * server context
	 */
	if (getcon_raw(&serverContext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get server process context")));

	/*
	 * client context
	 */
	if (!MyProcPort)
	{
		/*
		 * When the proces is not invoked as a backend of clietnt,
		 * it works as a server process and as a client process
		 * in same time.
		 */
		clientContext = serverContext;
	}
	else
	{
		if (getpeercon_raw(MyProcPort->sock, &clientContext) < 0)
		{
			/*
			 * fallbacked security context
			 *
			 * When getpeercon() API does not obtain the context of
			 * peer process, SEPGSQL_FALLBACK_CONTEXT environment
			 * variable is used as an alternative security context
			 * of the peer.
			 *
			 * getpeercon() needs the following condition to fail:
			 * - Connection come from remote host,
			 * - and, there is no labeled ipsec configuration between
			 *   localhost and remote host.
			 * - and, there is no static fallbacked context configuration
			 *   for the remote host.
			 */
			char	   *fallback = getenv("SEPGSQL_FALLBACK_CONTEXT");

			if (!fallback)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg
						 ("SELinux: could not get client process context")));

			if (security_check_context(fallback) < 0
				|| selinux_trans_to_raw_context(fallback, &clientContext) < 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: %s is not a valid context",
								fallback)));
		}
	}
}

/*
 * sepgsqlInitialize
 *
 * It initializes SE-PostgreSQL itself including assignment of shared
 * memory segment, reset of AVC, obtaining the client/server security
 * context and checks whether the client can access the required database,
 * or not.
 */
void
sepgsqlInitialize(bool bootstrap)
{
	char	   *dbname;

	sepgsqlAvcInit();

	initContexts();

	/*
	 * check db_database:{ access }
	 */
	if (IsBootstrapProcessingMode())
		dbname = "template1";
	else
	{
		Form_pg_database dbForm;
		HeapTuple	tuple;

		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(MyDatabaseId), 0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for database %u",
				 MyDatabaseId);
		dbForm = (Form_pg_database) GETSTRUCT(tuple);

		dbname = pstrdup(NameStr(dbForm->datname));

		ReleaseSysCache(tuple);
	}

	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 sepgsqlGetDatabaseContext(),
						 SECCLASS_DB_DATABASE,
						 DB_DATABASE__ACCESS,
						 dbname,
						 true);
}

/*
 * sepgsqlIsEnabled
 *
 * This function returns the state of SE-PostgreSQL when PGACE hooks
 * are invoked, to prevent to call sepgsqlXXXX() functions when
 * SE-PostgreSQL is disabled.
 *
 * We can config the state of SE-PostgreSQL in $PGDATA/postgresql.conf.
 * The GUC option "sepostgresql" can have the following four parameter.
 *
 * - default    : It always follows the in-kernel SELinux state. When it
 *                works in Enforcing mode, SE-PostgreSQL also works in
 *                Enforcing mode. Changes of in-kernel state are delivered
 *                to userspace SE-PostgreSQL soon, and SELinux state 
 *                monitoring process updates it rapidly.
 * - enforcing  : It always works in Enforcing mode. In-kernel SELinux
 *                has to be enabled.
 * - permissive : It always works in Permissive mode. In-kernel SELinux
 *                has to be enabled.
 * - disabled   : It disables SE-PostgreSQL feature. It works as if
 *                original PostgreSQL
 */

bool
sepgsqlIsEnabled(void)
{
	static int	enabled = -1;

	if (enabled < 0)
	{
		if (strcmp(sepostgresql_mode, "disabled") == 0)
			enabled = 0;
		else
		{
			int rc = is_selinux_enabled();

			if (strcmp(sepostgresql_mode, "default") == 0)
				enabled = rc;
			else if (strcmp(sepostgresql_mode, "permissice") == 0
					 || strcmp(sepostgresql_mode, "enforcing") == 0)
			{
				if (rc == 0)
					ereport(FATAL,
							(errcode(ERRCODE_SELINUX_ERROR),
							 errmsg("SELinux: disabled in kernel, but sepostgresql = %s",
									sepostgresql_mode)));
				enabled = 1;
			}
			else
			{
				ereport(FATAL,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: unknown state sepostgresql = %s",
								sepostgresql_mode)));
			}
		}
	}

	return enabled > 0 ? true : false;
}

/*
 * sepgsql_getcon(void)
 *
 * It returns security context of client
 */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	security_context_t context;
	Datum		labelTxt;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	if (selinux_raw_to_trans_context(clientContext, &context) < 0)
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

/*
 * sepgsql_getcon(void)
 *
 * It returns security context of server process
 */
Datum
sepgsql_getservcon(PG_FUNCTION_ARGS)
{
	security_context_t context;
	Datum		labelTxt;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	if (selinux_raw_to_trans_context(serverContext, &context) < 0)
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

static void
parse_to_context(security_context_t context,
				 char **user, char **role, char **type, char **range)
{
	security_context_t raw_context;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	if (selinux_trans_to_raw_context(context, &raw_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
	PG_TRY();
	{
		char	   *tmp;

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

/*
 * text sepgsql_get_user(text)
 *
 * It picks up the USER field of given security context.
 */
Datum
sepgsql_get_user(PG_FUNCTION_ARGS)
{
	char	   *user;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 &user, NULL, NULL, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(user));
}

/*
 * text sepgsql_set_user(text, text)
 *
 * It replaces the USER field of given security context by the second argument.
 */
Datum
sepgsql_set_user(PG_FUNCTION_ARGS)
{
	char	   *user, *role, *type, *range;
	char		buffer[1024];
	security_context_t newcon;
	Datum		result;

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

/*
 * text sepgsql_get_role(text)
 *
 * It picks up the ROLE field of given security context.
 */
Datum
sepgsql_get_role(PG_FUNCTION_ARGS)
{
	char	   *role;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 NULL, &role, NULL, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(role));
}

/*
 * text sepgsql_set_user(text, text)
 *
 * It replaces the ROLE field of given security context by the second argument.
 */
Datum
sepgsql_set_role(PG_FUNCTION_ARGS)
{
	char	   *user, *role, *type, *range;
	char		buffer[1024];
	security_context_t newcon;
	Datum		result;

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

/*
 * text sepgsql_get_type(text)
 *
 * It picks up the TYPE field of given security context.
 */
Datum
sepgsql_get_type(PG_FUNCTION_ARGS)
{
	char	   *type;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 NULL, NULL, &type, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(type));
}

/*
 * text sepgsql_set_user(text, text)
 *
 * It replaces the TYPE field of given security context by the second argument.
 */
Datum
sepgsql_set_type(PG_FUNCTION_ARGS)
{
	char	   *user, *role, *type, *range;
	char		buffer[1024];
	security_context_t newcon;
	Datum		result;

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

/*
 * text sepgsql_get_range(text)
 *
 * It picks up the RANGE field of given security context.
 */
Datum
sepgsql_get_range(PG_FUNCTION_ARGS)
{
	char	   *range;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 NULL, NULL, NULL, &range);
	PG_RETURN_TEXT_P(CStringGetTextDatum(range));
}

/*
 * text sepgsql_set_user(text, text)
 *
 * It replaces the RANGE field of given security context by the second argument.
 */
Datum
sepgsql_set_range(PG_FUNCTION_ARGS)
{
	char	   *user, *role, *type, *range;
	char		buffer[1024];
	security_context_t newcon;
	Datum		result;

	parse_to_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
					 &user, &role, &type, &range);
	if (range)
		snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
				 user, role, type, TextDatumGetCString(PG_GETARG_TEXT_P(1)));
	else
		snprintf(buffer, sizeof(buffer), "%s:%s:%s", user, role, type);
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

/*
 * SE-PostgreSQL legacy function support
 */
Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);
Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

Datum
sepgsql_tuple_perms(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_SELINUX_ERROR),
			 errmsg("%s is no longer supported", __FUNCTION__)));
	PG_RETURN_VOID();
}

Datum
sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_SELINUX_ERROR),
			 errmsg("%s is no longer supported", __FUNCTION__)));
	PG_RETURN_VOID();
}
