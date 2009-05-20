/*
 * src/backend/security/sepgsql/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/syscache.h"

/*
 * sepgsqlCheckDatabaseAccess
 *   checks db_database:{access} permission when the client logs-in
 *   the given database.
 *
 * sepgsqlCheckDatabaseSuperuser
 *   checks db_database:{superuser} permission when the client tries
 *   to perform as a superuser on the given databse.
 */
static bool
checkDatabaseCommon(Oid database_oid, access_vector_t perms)
{
	const char	   *audit_name;
	HeapTuple		tuple;
	bool			rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(database_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u",
			 database_oid);

	audit_name = sepgsqlAuditName(DatabaseRelationId, tuple);
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							   SEPG_CLASS_DB_DATABASE,
							   perms,
							   audit_name, false);
	ReleaseSysCache(tuple);

	return rc;
}

bool
sepgsqlCheckDatabaseAccess(Oid database_oid)
{
	return checkDatabaseCommon(database_oid,
							   SEPG_DB_DATABASE__ACCESS);
}

bool
sepgsqlCheckDatabaseSuperuser(void)
{
	return checkDatabaseCommon(MyDatabaseId,
							   SEPG_DB_DATABASE__SUPERUSER);
}

/*
 * sepgsqlCheckSchemaSearch
 *   checks db_schema:{search} permission when the given namespace
 *   is searched.
 *
 *   db_schema:{add_object remove_object} permissions is not now
 *   implemented.
 */
static bool
sepgsqlCheckSchemaCommon(Oid nsid, access_vector_t required, bool abort)
{
	const char		   *audit_name;
	security_class_t	tclass;
	HeapTuple			tuple;
	bool rc;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nsid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace: %u", nsid);

	audit_name = sepgsqlAuditName(NamespaceRelationId, tuple);
	tclass = sepgsqlTupleObjectClass(NamespaceRelationId, tuple);
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							   tclass,
							   required,
							   audit_name, false);
	ReleaseSysCache(tuple);

	return rc;
}

bool sepgsqlCheckSchemaSearch(Oid nsid)
{
	return sepgsqlCheckSchemaCommon(nsid, SEPG_DB_SCHEMA__SEARCH, false);
}

/*
 * sepgsqlCheckTableLock
 *   checks db_table:{lock} permission when the client tries to
 *   aquire explicit lock on the given relation.
 *
 * sepgsqlCheckTableTruncate
 *   checks db_table:{delete} permission when the client tries to
 *   truncate the given relation.
 */
static void
checkTableCommon(Oid table_oid, access_vector_t perms)
{
	const char		   *audit_name;
	security_class_t	tclass;
	HeapTuple			tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(table_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", table_oid);

	tclass = sepgsqlTupleObjectClass(RelationRelationId, tuple);
	if (tclass == SEPG_CLASS_DB_TABLE)
	{
		audit_name = sepgsqlAuditName(RelationRelationId, tuple);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							  SEPG_CLASS_DB_TABLE,
							  perms,
							  audit_name, true);
	}
	ReleaseSysCache(tuple);
}

void
sepgsqlCheckTableLock(Oid table_oid)
{
	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{lock} permission */
	checkTableCommon(table_oid, SEPG_DB_TABLE__LOCK);
}

void
sepgsqlCheckTableTruncate(Relation rel)
{
	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{delete} permission */
	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE);
}

void
sepgsqlCheckTableReference(Relation rel, int16 *attnums, int natts)
{
	const char *audit_name;
	HeapTuple	tuple;
	int			i;

	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{reference} permission */
	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__REFERENCE);

	/* check db_column:{reference} permission */
	for (i=0; i < natts; i++)
	{
		tuple = SearchSysCache(ATTNUM,
							   RelationGetRelid(rel),
							   attnums[i], 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %u of %s",
				 attnums[i], RelationGetRelationName(rel));

		audit_name = sepgsqlAuditName(AttributeRelationId, tuple);
		sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							  SEPG_CLASS_DB_COLUMN,
							  SEPG_DB_COLUMN__REFERENCE,
							  audit_name, true);
		ReleaseSysCache(tuple);
	}
}

/*
 * sepgsqlCheckSequenceXXXX
 *
 *   It checks permissions on db_sequence objects.
 */
static void
sepgsqlCheckSequenceCommon(Oid seqid, access_vector_t required)
{
	const char *audit_name;
	HeapTuple tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(seqid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for sequence: %u", seqid);

	audit_name = sepgsqlAuditName(RelationRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SEPG_CLASS_DB_SEQUENCE,
						  required,
						  audit_name, true);
	ReleaseSysCache(tuple);
}

void sepgsqlCheckSequenceGetValue(Oid seqid)
{
	sepgsqlCheckSequenceCommon(seqid, SEPG_DB_SEQUENCE__GET_VALUE);
}

void sepgsqlCheckSequenceNextValue(Oid seqid)
{
	sepgsqlCheckSequenceCommon(seqid, SEPG_DB_SEQUENCE__NEXT_VALUE);
}

void sepgsqlCheckSequenceSetValue(Oid seqid)
{
	sepgsqlCheckSequenceCommon(seqid, SEPG_DB_SEQUENCE__SET_VALUE);
}

/*
 * sepgsqlCheckProcedureExecute
 *   checks db_procedure:{execute} permission when the client tries
 *   to invoke the given SQL function.
 */
bool sepgsqlCheckProcedureExecute(Oid proc_oid)
{
	const char *audit_name;
	HeapTuple tuple;
	bool rc;

	if (!sepgsqlIsEnabled())
		return true;

	/*
	 * check db_procedure:{execute} permission
	 */
	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(proc_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure: %u", proc_oid);

	audit_name = sepgsqlAuditName(ProcedureRelationId, tuple);
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							   SEPG_CLASS_DB_PROCEDURE,
							   SEPG_DB_PROCEDURE__EXECUTE,
							   audit_name, false);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsqlCheckProcedureEntrypoint
 *   checks whether the given function call causes domain transition,
 *   or not. If it needs a domain transition, it injects a wrapper
 *   function to invoke it under new domain.
 */
struct TrustedProcedureCache
{
	FmgrInfo	flinfo;
	char		newcon[1];
};

static Datum
sepgsqlTrustedProcedure(PG_FUNCTION_ARGS)
{
	struct TrustedProcedureCache *tcache;
	security_context_t	save_context;
	FmgrInfo		   *save_flinfo;
	Datum				result;

	tcache = fcinfo->flinfo->fn_extra;
	Assert(tcache != NULL);

	save_context = sepgsqlSwitchClient(tcache->newcon);
	save_flinfo = fcinfo->flinfo;
	fcinfo->flinfo = &tcache->flinfo;

	PG_TRY();
	{
		result = FunctionCallInvoke(fcinfo);
	}
	PG_CATCH();
	{
		sepgsqlSwitchClient(save_context);
		fcinfo->flinfo = save_flinfo;
		PG_RE_THROW();
	}
	PG_END_TRY();
	sepgsqlSwitchClient(save_context);
	fcinfo->flinfo = save_flinfo;

	return result;
}

void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *flinfo, HeapTuple protup)
{
	struct TrustedProcedureCache *tcache;
	security_context_t	newcon;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	newcon = sepgsqlClientCreateLabel(HeapTupleGetSecLabel(protup),
									  SEPG_CLASS_PROCESS);

	/* Do nothing, if it is not a trusted procedure */
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
		return;

	/* check db_procedure:{entrypoint} */
	audit_name = sepgsqlAuditName(ProcedureRelationId, protup);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(protup),
						  SEPG_CLASS_DB_PROCEDURE,
						  SEPG_DB_PROCEDURE__ENTRYPOINT,
						  audit_name, true);

	/* check process:{transition} */
	sepgsqlComputePerms(sepgsqlGetClientLabel(),
						newcon,
						SEPG_CLASS_PROCESS,
						SEPG_PROCESS__TRANSITION,
						NULL, true);

	/* setup trusted procedure */
	tcache = MemoryContextAllocZero(flinfo->fn_mcxt,
							sizeof(*tcache) + strlen(newcon));
	memcpy(&tcache->flinfo, flinfo, sizeof(*flinfo));
	strcmp(tcache->newcon, newcon);
	flinfo->fn_addr = sepgsqlTrustedProcedure;
	flinfo->fn_extra = tcache;
}

/*
 * sepgsqlAllowFunctionInlined
 *   It provides the optimizer a hint whether the given SQL function
 *   can be inlined, or not. If it can be configured as a trusted
 *   procedure, we should not allow it inlined.
 */
bool
sepgsqlAllowFunctionInlined(HeapTuple proc_tuple)
{
	security_context_t	context;

	if (!sepgsqlIsEnabled())
		return true;

	context = sepgsqlClientCreateLabel(HeapTupleGetSecLabel(proc_tuple),
									   SEPG_CLASS_PROCESS);
	/*
	 * If the security context of client is unchange
	 * before or after invocation of the functions,
	 * it is not a trusted procedure, so it can be
	 * inlined due to performance purpose.
	 */
	if (strcmp(sepgsqlGetClientLabel(), context) == 0)
		return true;

	return false;
}
