/*
 * src/backend/utils/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"




void sepgsqlDatabaseAccess(Oid db_oid)
{
	HeapTuple tuple;
	const char *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(db_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u", db_oid);

	audit_name = sepgsqlAuditName(DatabaseRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SECCLASS_DB_DATABASE,
						  DB_DATABASE__ACCESS,
						  audit_name);
	ReleaseSysCache(tuple);
}

void sepgsqlProcedureExecute(Oid proc_oid)
{
	HeapTuple tuple;
	const char *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(proc_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure: %u", proc_oid);

	audit_name = sepgsqlAuditName(ProcedureRelationId, tuple);
	sepgsqlClientHasPermis(HeapTupleGetSecLabel(tuple),
						   SECCLASS_DB_PROCEDURE,
						   DB_PROCEDURE__EXECUTE,
						   audit_name);
	ReleaseSysCache(tuple);
}


