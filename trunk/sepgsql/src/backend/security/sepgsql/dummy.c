/*
 * src/backend/security/sepgsql/dummy.c
 *   Dummy functions for SE-PgSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "security/sepgsql.h"

bool
sepgsql_is_enabled(void)
{
	return false;
}

char *
sepgsql_get_client_context(void)
{
	elog(ERROR, "SE-PgSQL is disabled in this build");

	return NULL;
}

char *
sepgsql_get_unlabeled_context(void)
{
	elog(ERROR, "SE-PgSQL is disabled in this build");

	return NULL;
}

extern bool
sepgsql_compute_perms(char *scontext, char *tcontext,
                      uint16 tclass, uint32 required,
                      const char *audit_name, bool abort)
{
	elog(ERROR, "SE-PgSQL is disabled in this build");

	return false;
}

char *
sepgsql_compute_create(char *scontext, char *tcontext, uint16 tclass)
{
	elog(ERROR, "SE-PgSQL is disabled in this build");

	return NULL;
}

char *
sepgsql_mcstrans_in(char *trans_context)
{
	elog(ERROR, "SE-PgSQL is disabled in this build");

	return NULL;
}

char *
sepgsql_mcstrans_out(char *raw_context)
{
	elog(ERROR, "SE-PgSQL is disabled in this build");

	return NULL;
}
