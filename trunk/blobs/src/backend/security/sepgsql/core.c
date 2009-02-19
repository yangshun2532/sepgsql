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
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
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
sepgsqlSwitchClient(security_context_t new_client)
{
	char *old_client = sepgsqlGetClientLabel();

	clientLabel = new_client;

	PG_TRY();
	{
		sepgsqlAvcSwitchClient();
	}
	PG_CATCH();
	{
		clientLabel = old_client;
		PG_RE_THROW();
	}
	PG_END_TRY();

	return new_client;
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
	HeapTuple			tuple;
	security_context_t	dbcon;

	if (IsBootstrapProcessingMode())
	{
		static security_context_t	databaseLabel = NULL;

		if (!databaseLabel)
		{
			security_class_t	tclass
				= string_to_security_class("db_database");

			if (security_compute_create_raw(sepgsqlGetClientLabel(),
											sepgsqlGetClientLabel(),
											tclass, &databaseLabel) < 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: unable to compute database context")));
		}
		return pstrdup(databaseLabel);
	}

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u",
			 MyDatabaseId);

	dbcon = securityLookupSecurityLabel(HeapTupleGetSecLabel(tuple));
	if (!dbcon || !sepgsqlCheckValidSecurityLabel(dbcon))
		dbcon = pstrdup(sepgsqlGetUnlabeledLabel());

	ReleaseSysCache(tuple);

	return dbcon;
}

sepgsql_sid_t
sepgsqlGetDatabaseSid(void)
{
	HeapTuple		tuple;
	sepgsql_sid_t	dbsid;

	if (IsBootstrapProcessingMode())
	{
		security_context_t	dbcon
			= sepgsqlGetDatabaseLabel();

		dbsid = securityLookupSecurityId(dbcon);
	}
	else
	{
		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(MyDatabaseId),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "SELinux: cache lookup failed for database: %u",
				 MyDatabaseId);

		dbsid = HeapTupleGetSecLabel(tuple);

		ReleaseSysCache(tuple);
	}

	return dbsid;
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
	security_context_t context;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	context = sepgsqlGetClientLabel();
	context = sepgsqlSecurityLabelTransOut(context);
	return CStringGetTextDatum(context);
}

Datum
sepgsql_server_getcon(PG_FUNCTION_ARGS)
{
	security_context_t context;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	context = sepgsqlGetServerLabel();
	context = sepgsqlSecurityLabelTransOut(context);
	return CStringGetTextDatum(context);
}

Datum
sepgsql_mcstrans(PG_FUNCTION_ARGS)
{
	security_context_t context;
	text   *labelTxt = PG_GETARG_TEXT_P(0);

	context = text_to_cstring(labelTxt);
	context = sepgsqlSecurityLabelTransOut(context);

	return CStringGetTextDatum(context);
}

/*
 * sepgsql_(get|set)_(user|role|type|range)
 *   get/set a component of security context.
 */
static void
parse_security_context(security_context_t context,
					   char **user, char **role, char **type, char **range)
{
	security_context_t	raw_context;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	if (selinux_trans_to_raw_context(context, &raw_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label: %s", context)));

	PG_TRY();
	{
		char	   *tok;

		tok = strtok(raw_context, ":");
		if (user)
			*user = (!tok ? NULL : pstrdup(tok));

		tok = strtok(NULL, ":");
		if (role)
			*role = (!tok ? NULL : pstrdup(tok));

		tok = strtok(NULL, ":");
		if (type)
			*type = (!tok ? NULL : pstrdup(tok));

		tok = strtok(NULL, "\0");
		if (range)
			*range = (!tok ? NULL : pstrdup(tok));
	}
	PG_CATCH();
	{
		freecon(raw_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(raw_context);
}

Datum
sepgsql_get_user(PG_FUNCTION_ARGS)
{
	char	   *user;

	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   &user, NULL, NULL, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(user));
}

Datum
sepgsql_get_role(PG_FUNCTION_ARGS)
{
	char	   *role;

	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   NULL, &role, NULL, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(role));
}

Datum
sepgsql_get_type(PG_FUNCTION_ARGS)
{
	char	   *type;

	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   NULL, NULL, &type, NULL);
	PG_RETURN_TEXT_P(CStringGetTextDatum(type));
}

Datum
sepgsql_get_range(PG_FUNCTION_ARGS)
{
	char	   *range;

	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   NULL, NULL, NULL, &range);
	PG_RETURN_TEXT_P(CStringGetTextDatum(range));
}

Datum
sepgsql_set_user(PG_FUNCTION_ARGS)
{
	security_context_t	newcon, result;
	char	   *user, *role, *type, *range;
	int			length;

	user = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   NULL, &role, &type, &range);

	length = (!user ? 0 : strlen(user)) + (!role ? 0 : strlen(role))
		+ (!type ? 0 : strlen(type)) + (!range ? 0 : strlen(range)) + 4;
	newcon = palloc(length);

	if (!range)
		snprintf(newcon, length, "%s:%s:%s", user, role, type);
	else
		snprintf(newcon, length, "%s:%s:%s:%s", user, role, type, range);

	result = sepgsqlSecurityLabelTransOut(newcon);

	PG_RETURN_TEXT_P(CStringGetTextDatum(result));
}

Datum
sepgsql_set_role(PG_FUNCTION_ARGS)
{
	security_context_t	newcon, result;
	char	   *user, *role, *type, *range;
	int			length;

	role = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   &user, NULL, &type, &range);

	length = (!user ? 0 : strlen(user)) + (!role ? 0 : strlen(role))
		+ (!type ? 0 : strlen(type)) + (!range ? 0 : strlen(range)) + 4;
	newcon = palloc(length);

	if (!range)
		snprintf(newcon, length, "%s:%s:%s", user, role, type);
	else
		snprintf(newcon, length, "%s:%s:%s:%s", user, role, type, range);

	result = sepgsqlSecurityLabelTransOut(newcon);

	PG_RETURN_TEXT_P(CStringGetTextDatum(result));
}

Datum
sepgsql_set_type(PG_FUNCTION_ARGS)
{
	security_context_t	newcon, result;
	char	   *user, *role, *type, *range;
	int			length;

	type = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   &user, &role, NULL, &range);

	length = (!user ? 0 : strlen(user)) + (!role ? 0 : strlen(role))
		+ (!type ? 0 : strlen(type)) + (!range ? 0 : strlen(range)) + 4;
	newcon = palloc(length);

	if (!range)
		snprintf(newcon, length, "%s:%s:%s", user, role, type);
	else
		snprintf(newcon, length, "%s:%s:%s:%s", user, role, type, range);

	result = sepgsqlSecurityLabelTransOut(newcon);

	PG_RETURN_TEXT_P(CStringGetTextDatum(result));
}

Datum
sepgsql_set_range(PG_FUNCTION_ARGS)
{
	security_context_t	newcon, result;
	char	   *user, *role, *type, *range;
	int			length;

	range = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	parse_security_context(TextDatumGetCString(PG_GETARG_TEXT_P(0)),
						   &user, &role, &type, NULL);

	length = (!user ? 0 : strlen(user)) + (!role ? 0 : strlen(role))
		+ (!type ? 0 : strlen(type)) + (!range ? 0 : strlen(range)) + 4;
	newcon = palloc(length);

	if (!range)
		snprintf(newcon, length, "%s:%s:%s", user, role, type);
	else
		snprintf(newcon, length, "%s:%s:%s:%s", user, role, type, range);

	result = sepgsqlSecurityLabelTransOut(newcon);

	PG_RETURN_TEXT_P(CStringGetTextDatum(result));
}
