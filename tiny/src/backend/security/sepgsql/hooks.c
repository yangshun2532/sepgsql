/*
 * src/backend/security/sepgsql/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "utils/syscache.h"

/* ------------------------------------------------------------
 * Hooks corresponding to db_database object class
 * ------------------------------------------------------------ */

static bool
checkDatabaseCommon(Oid database_oid, uint32 required, bool abort)
{
	HeapTuple	tuple;
	bool		rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(database_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", database_oid);

	rc = sepgsqlClientHasPermsTup(DatabaseRelationId, tuple,
								  SEPG_CLASS_DB_DATABASE,
								  required, abort);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsqlCheckDatabaseConnect
 *
 * It checks db_database:{connect} permission on the database,
 * and returns its decision.
 *
 * This check is equivalent to ACL_CONNECT privilege, and
 * invoked from pg_databse_aclcheck(). So, it must not be
 * bypassed, even if client has superuser privilege.
 */
bool
sepgsqlCheckDatabaseAccess(Oid database_oid)
{
	return checkDatabaseCommon(database_oid,
							   SEPG_DB_DATABASE__ACCESS, false);
}

/*
 * sepgsqlCheckDatabaseSuperuser
 *
 * It checks db_database:{superuser} permission on the current
 * database, and returns its decision.
 *
 * This check is equivalent to the database superuser privilege.
 * The superuser_arg() always calls the hook before it returns
 * the state of superuser privilege.
 */
bool
sepgsqlCheckDatabaseSuperuser(void)
{
	return checkDatabaseCommon(MyDatabaseId,
							   SEPG_DB_DATABASE__SUPERUSER, false);
}

/* ------------------------------------------------------------
 * Hooks corresponding to db_schema object class
 * ------------------------------------------------------------ */

static bool
checkSchemaCommon(Oid namespace_oid, uint32 required, boot abort)
{
	HeapTuple	tuple;
	bool		rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(namespace_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace: %u", namespace_oid);

	rc = sepgsqlClientHasPermsTup(NamespaceRelationId, tuple,
								  (!isAnyTempNamespace(namespace_oid)
								   ? SEPG_CLASS_DB_SCHEMA
								   : SEPG_CLASS_DB_SCHEMA_TEMP),
								  required, abort);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsqlCheckSchemaSearch
 *
 * It checks db_schema:{search} permission on the namespace,
 * and returns its decision.
 *
 * This check is equivalent to ACL_USAGE privilge on namespaces,
 * and invoked from pg_namespace_aclcheck(). So, it must not be
 * bypassed, even if client has superuser privilege.
 */
bool
sepgsqlCheckSchemaSearch(Oid namespace_oid)
{
	return sepgsqlCheckSchemaCommon(namespace_oid,
									SEPG_DB_SCHEMA__SEARCH, false);
}

/* ------------------------------------------------------------
 * Hooks corresponding to db_procedure object class
 * ------------------------------------------------------------ */

static bool
checkProcedureCommon(Oid proc_oid, uint32 required, bool abort)
{
	HeapTuple	tuple;
	bool		rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(proc_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for procedure: %u", proc_oid);

	rc = sepgsqlClientHasPermsTup(ProcedureRelationId, tuple,
								  SEPG_CLASS_DB_PROCEDURE,
								  required, abort);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsqlCheckProcedureExecute
 *
 * It checks db_procedure:{execute} permission on the procedure, and
 * returns its decision.
 *
 * This check is equivalent to ACL_EXECUTE privilege on procedures,
 * and invoked from pg_proc_aclcheck(). So, it must not be bypassed,
 * even if client has superuser privilege.
 */
bool
sepgsqlCheckProcedureExecute(Oid proc_oid)
{
	return checkProcedureCommon(proc_oid,
								SEPG_DB_PROCEDURE__EXECUTE, false);
}
