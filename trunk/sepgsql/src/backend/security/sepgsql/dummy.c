/*
 * src/backend/security/sepgsql/dummy.c
 *   Dummy functions for SE-PgSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "security/sepgsql.h"

/*
 * Dummy functions for selinux.c
 * -----------------------------
 */
void sepgsql_initialize(void)
{
	/* do nothing */
}

bool sepgsql_is_enabled(void)
{
	return false;	/* always disabled */
}




/*
 * Dummy functions for checker.c
 * -----------------------------
 */





/*
 * Dummy functions for hooks.c
 * ---------------------------
 */










/*
 * Dummy functions for utils.c
 * ---------------------------
 */
Datum
sepgsql_fn_getcon(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("SE-PostgreSQL is disabled in this build")));
}

Datum
sepgsql_fn_database_getcon(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("SE-PostgreSQL is disabled in this build")));
}

Datum
sepgsql_fn_schema_getcon(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("SE-PostgreSQL is disabled in this build")));
}

Datum
sepgsql_fn_table_getcon(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("SE-PostgreSQL is disabled in this build")));
}

Datum
sepgsql_fn_column_getcon(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("SE-PostgreSQL is disabled in this build")));
}

Datum
sepgsql_fn_compute_create(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("SE-PostgreSQL is disabled in this build")));
}
