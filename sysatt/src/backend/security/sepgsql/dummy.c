/*
 * src/backend/utils/sepgsql/dummy.c
 *    A set of stubs when SE-PostgreSQL is not activated
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "security/sepgsql.h"

static Datum
unavailable_function(const char *fn_name)
{
	ereport(ERROR,
			(errcode(ERRCODE_SELINUX_ERROR),
			 errmsg("function \"%s\" is not available", fn_name)));
	PG_RETURN_VOID();
}

Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__);
}

Datum
sepgsql_server_getcon(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__);
}

Datum
sepgsql_mcstrans(PG_FUNCTION_ARGS)
{
	return unavailable_function(__FUNCTION__);
}
