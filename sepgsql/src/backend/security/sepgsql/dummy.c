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

Datum
sepgsql_database_relabel(Oid datOid, DefElem *datLabel)
{
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("SE-PostgreSQL is disabled")));

	return PointerGetDatum(NULL);
}


