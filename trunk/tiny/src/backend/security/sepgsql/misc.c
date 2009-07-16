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

static security_context_t clientLabel = NULL;
static security_context_t serverLabel = NULL;

/*
 * sepgsqlGetServerLabel
 *
 * It returns the security label of server process.
 */
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

/*
 * sepgsqlGetClientLabel
 *
 * It returns the security label of client process which is
 * obtained from getpeercon(3) API.
 * If the backend is not launched with a certain remote client,
 * it returns the security label of itself.
 */
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

/*
 * sepgsqlSwitchClient
 *
 * It switches the security label of the client temporary.
 * If someone raises an error during an alternative security
 * label is applied, it is not recovered automatically.
 * In this case, caller needs to acquire errors using PG_TRY().
 */
char *
sepgsqlSwitchClient(char *new_label)
{
	char *old_label = sepgsqlGetClientLabel();

	clientLabel = new_label;

	return old_label;
}

/*
 * sepgsqlIsEnabled
 *
 * It returns true, if SE-PostgreSQL is available.
 * All the security hooks shall check sepgsqlIsEnabled() on the head.
 * This status is determined with two factors. The one is GUC option
 * "sepostgresql=on/off", and the other is SELinux's status on the
 * system. Both of them must be enabled, when SE-PostgreSQL is available.
 */
bool sepostgresql_enabled;

bool
sepgsqlIsEnabled(void)
{
	static int enabled = -1;	/* unchecked */

	if (!sepostgresql_enabled)
		return false;

	if (enabled < 0)
		enabled = is_selinux_enabled();

	return enabled > 0 ? true : false;
}

/*
 * sepgsql_getcon
 *
 * It returns security label of the client process.
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
	context = sepgsqlTransSecLabelOut(context);
	return CStringGetTextDatum(context);
}

/*
 * sepgsql_server_getcon
 *
 * It returns security label of the server process.
 */
Datum
sepgsql_server_getcon(PG_FUNCTION_ARGS)
{
	security_context_t context;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	context = sepgsqlGetServerLabel();
	context = sepgsqlTransSecLabelOut(context);
	return CStringGetTextDatum(context);
}
