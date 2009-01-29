/*
 * src/backend/utils/sepgsql/core.c
 *    The core facility of SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "utils/sepgsql.h"


const security_context_t
sepgsqlGetServerContext(void)
{
	static security_context_t serverContext = NULL;

	if (serverContext)
		return serverContext;

	if (getcon_raw(&serverContext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get server context")));

	return serverContext;
}

const security_context_t
sepgsqlGetClientContext(void)
{
	static security_context_t clientContext = NULL;

	if (clientContext)
		return clientContext;

	if (!MyProcPort)
	{
		/*
		 * When the proces is not invoked as a backend of clietnt,
		 * it works as a server process and as a client process
		 * in same time.
		 */
		clientContext = sepgsqlGetServerContext();
	}
	else
	{
		/*
		 * SELinux provides getpeercon(3) which enables to obtain
		 * the security context of peer process.
		 * If MyProcPort->sock is unix domain socket, no special
		 * configuration is necessary. If it is tcp/ip socket,
		 * labeled IPsec or fallback context to be configured.
		 */
		if (getpeercon_raw(MyProcPort->sock, &clientContext) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not get client context")));
	}

	return clientContext;
}

const security_context_t
sepgsqlGetUnlabeledContext(void)
{
	static security_context_t unlabeledContext = NULL;

	if (unlabeledContext)
		return unlabeledContext;

	if (security_get_initial_context_raw("unlabeled", &unlabeledContext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get unlabeled context")));

	return unlabeledContext;
}

const security_context_t
sepgsqlGetDatabaseContext(void)
{
	security_context_t result;
	HeapTuple tuple;

	if (IsBootstrapProcessingMode())
	{
		static security_context_t dcontext = NULL;

		if (!dbcontext)
		{
			security_class_t tclass
				= string_to_security_class("db_database");

			if (tclass == 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: db_database class is not installed")));

			if (security_compute_create_raw(sepgsqlGetClientContext(),
											sepgsqlGetClientContext(),
											tclass, &dcontext) < 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("SELinux: could not get database context")));
		}
		return pstrdup(dcontext);
	}

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u", MyDatabaseId);

	result = sepgsqlLookupSecurityLabel(HeapTupleGetSecLabel(tuple));
	if (!result || !sepgsqlCheckValidSecurityLabel(result))
		result = sepgsqlGetUnlabeledContext();

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
		security_context_t dcontext
			= sepgsqlGetDatabaseContext();

		return sepgsqlSecurityLabelToSid(dcontext);
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
 *   When functions under src/backend/utils/* are invoked, they have to
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
 * SE-PostgreSQL specific functions
 */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

}

Datum
sepgsql_server_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

}

Datum
sepgsql_database_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));
}

Datum
sepgsql_table_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

}

Datum
sepgsql_column_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));


}

Datum
sepgsql_procedure_getcon(PG_FUNCTION_ARGS)
{
	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

}
