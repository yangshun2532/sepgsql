/*
 * src/backend/security/sepgsql/core.c
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

/*
 * sepgsql_(get|set)_(user|role|type|range)
 *   get/set a component of security context.
 */
static void
parse_security_context(security_context_t context,
					   char **user, char **role, char **type, char **range)
{
	security_context_t	raw_context;
	char	   *tok;

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
	security_context_t	context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *user;

	parse_security_context(context, &user, NULL, NULL, NULL);
	if (!user)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not extract user of \"%s\"", context)));

	PG_RETURN_TEXT_P(CStringGetTextDatum(user));
}

Datum
sepgsql_get_role(PG_FUNCTION_ARGS)
{
	security_context_t	context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *role;

	parse_security_context(context, NULL, &role, NULL, NULL);
	if (!role)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not extract role of \"%s\"", context)));

	PG_RETURN_TEXT_P(CStringGetTextDatum(role));
}

Datum
sepgsql_get_type(PG_FUNCTION_ARGS)
{
	security_context_t	context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *type;

	parse_security_context(context, NULL, NULL, &type, NULL);
	if (!type)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not extract type of \"%s\"", context)));

	PG_RETURN_TEXT_P(CStringGetTextDatum(type));
}

Datum
sepgsql_get_range(PG_FUNCTION_ARGS)
{
	security_context_t context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *range;

	parse_security_context(context, NULL, NULL, NULL, &range);
	if (!range)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not extract range of \"%s\"", context)));

	PG_RETURN_TEXT_P(CStringGetTextDatum(range));
}

static Datum
sepgsql_set_common(char *context, char *user, char *role, char *type, char *range)
{
	StringInfoData	newcon;

	parse_security_context(context,
						   !user	? &user  : NULL,
						   !role	? &role	 : NULL,
						   !type	? &type  : NULL,
						   !range	? &range : NULL);
	if (!user || !role || !type)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: invalid security context: \"%s\"", context)));

	initStringInfo(&newcon);
	appendStringInfo(&newcon, "%s:%s:%s", user, role, type);
	if (range)
		appendStringInfo(&newcon, ":%s", range);

	return CStringGetTextDatum(sepgsqlSecurityLabelTransOut(newcon.data));
}

Datum
sepgsql_set_user(PG_FUNCTION_ARGS)
{
	security_context_t	context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *user = TextDatumGetCString(PG_GETARG_TEXT_P(1));

	return sepgsql_set_common(context, user, NULL, NULL, NULL);
}

Datum
sepgsql_set_role(PG_FUNCTION_ARGS)
{
	security_context_t	context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *role = TextDatumGetCString(PG_GETARG_TEXT_P(1));

	return sepgsql_set_common(context, NULL, role, NULL, NULL);
}

Datum
sepgsql_set_type(PG_FUNCTION_ARGS)
{
	security_context_t	context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *type = TextDatumGetCString(PG_GETARG_TEXT_P(1));

	return sepgsql_set_common(context, NULL, NULL, type, NULL);
}

Datum
sepgsql_set_range(PG_FUNCTION_ARGS)
{
	security_context_t	context = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char	   *range = TextDatumGetCString(PG_GETARG_TEXT_P(1));

	return sepgsql_set_common(context, NULL, NULL, NULL, range);
}
