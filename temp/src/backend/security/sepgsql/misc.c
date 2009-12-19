/*
 * src/backend/security/sepgsql/misc.c
 *    Miscellaneous facilities in SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"

/*
 * SE-PostgreSQL specific functions
 */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	security_context_t context;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux: disabled now")));

	context = sepgsqlGetClientLabel();
	context = sepgsqlTransSecLabelOut(context);
	return CStringGetTextDatum(context);
}

Datum
sepgsql_server_getcon(PG_FUNCTION_ARGS)
{
	char   *context;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux: disabled now")));

	context = sepgsqlGetServerLabel();
	context = sepgsqlTransSecLabelOut(context);

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
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux: disabled now")));

	if (selinux_trans_to_raw_context(context, &raw_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("could not translate mls label: %s", context)));

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
				(errcode(ERRCODE_INVALID_SECURITY_LABEL),
				 errmsg("could not extract user of \"%s\"", context)));

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
				(errcode(ERRCODE_INVALID_SECURITY_LABEL),
				 errmsg("could not extract role of \"%s\"", context)));

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
				(errcode(ERRCODE_INVALID_SECURITY_LABEL),
				 errmsg("could not extract type of \"%s\"", context)));

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
				(errcode(ERRCODE_INVALID_SECURITY_LABEL),
				 errmsg("could not extract range of \"%s\"", context)));

	PG_RETURN_TEXT_P(CStringGetTextDatum(range));
}

static Datum
sepgsql_set_common(char *context,
				   char *user, char *role, char *type, char *range)
{
	StringInfoData	newcon;

	parse_security_context(context,
						   !user	? &user  : NULL,
						   !role	? &role	 : NULL,
						   !type	? &type  : NULL,
						   !range	? &range : NULL);
	if (!user || !role || !type)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_LABEL),
				 errmsg("invalid security context: \"%s\"", context)));

	initStringInfo(&newcon);
	appendStringInfo(&newcon, "%s:%s:%s", user, role, type);
	if (range)
		appendStringInfo(&newcon, ":%s", range);

	return CStringGetTextDatum(sepgsqlTransSecLabelOut(newcon.data));
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
