/*
 * src/backend/utils/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_aggregate.h"
#include "catalog/pg_amproc.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_language.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/syscache.h"

/*
 * sepgsqlCheckDatabaseAccess
 * sepgsqlCheckDatabaseSuperuser
 *
 *
 */
static bool
checkDatabaseCommon(Oid database_oid, access_vector_t perms)
{
	const char	   *audit_name;
	sepgsql_sid_t	database_sid;
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
	database_sid = HeapTupleGetSecLabel(DatabaseRelationId, tuple);
	rc = sepgsqlClientHasPerms(database_sid,
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
 * sepgsqlCheckTableLock
 * sepgsqlCheckTableTruncate
 *   They check db_table:{lock} and db_table:{delete} permission
 *   for the given relation.
 */
static bool
checkTableCommon(Oid table_oid, access_vector_t perms)
{
	const char		   *audit_name;
	security_class_t	tclass;
	sepgsql_sid_t		table_sid;
	HeapTuple			tuple;
	bool				rc = true;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(table_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", table_oid);

	tclass = sepgsqlTupleObjectClass(RelationRelationId, tuple);
	if (tclass == SEPG_CLASS_DB_TABLE)
	{
		audit_name = sepgsqlAuditName(RelationRelationId, tuple);
		table_sid = HeapTupleGetSecLabel(RelationRelationId, tuple);
		rc = sepgsqlClientHasPerms(table_sid,
								   SEPG_CLASS_DB_TABLE,
								   perms,
								   audit_name, false);
	}
	ReleaseSysCache(tuple);

	return rc;
}

bool
sepgsqlCheckTableLock(Oid table_oid)
{
	return checkTableCommon(table_oid, SEPG_DB_TABLE__LOCK);
}

bool
sepgsqlCheckTableTruncate(Relation rel)
{
	return checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE);
}

/*
 * Function related hooks
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
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(ProcedureRelationId, tuple),
							   SEPG_CLASS_DB_PROCEDURE,
							   SEPG_DB_PROCEDURE__EXECUTE,
							   audit_name, false);
	ReleaseSysCache(tuple);

	return rc;
}

static Datum
sepgsqlTrustedProcInvoker(PG_FUNCTION_ARGS)
{
	security_context_t old_client;
	FmgrInfo *finfo = fcinfo->flinfo;
	Datum retval;

	/*
	 * Set new domain and invocation
	 */
	old_client = sepgsqlSwitchClient(finfo->sepgsql_label);

	PG_TRY();
	{
		retval = finfo->sepgsql_addr(fcinfo);
	}
	PG_CATCH();
	{
		sepgsqlSwitchClient(old_client);
		PG_RE_THROW();
	}
	PG_END_TRY();

	sepgsqlSwitchClient(old_client);

	return retval;
}

void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *finfo, HeapTuple protup)
{
	MemoryContext		oldctx;
	sepgsql_sid_t		prosid;
	security_context_t	newcon;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	/*
	 * NOTE: It is not available to set up builtin functions as
	 * trusted procedure now, because it needs to invoke builtin
	 * functions to search system caches, then it also invokes
	 * fmgr_info_cxt_security() and makes infinite function call.
	 * This limitation should be fixed later.
	 * (It is same as security definer also)
	 */

	oldctx = MemoryContextSwitchTo(finfo->fn_mcxt);

	prosid = HeapTupleGetSecLabel(ProcedureRelationId, protup);
	newcon = sepgsqlClientCreateLabel(prosid, SEPG_CLASS_PROCESS);
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
	{
		MemoryContextSwitchTo(oldctx);
		return;
	}
	/* db_procedure:{entrypoint}, if trusted procedure */
	audit_name = sepgsqlAuditName(ProcedureRelationId, protup);
	sepgsqlClientHasPerms(prosid,
						  SEPG_CLASS_DB_PROCEDURE,
						  SEPG_DB_PROCEDURE__ENTRYPOINT,
						  audit_name, true);

	/* process:{transition}, if trusted procedure */
	sepgsqlComputePerms(sepgsqlGetClientLabel(),
						newcon,
						SEPG_CLASS_PROCESS,
						SEPG_PROCESS__TRANSITION,
						NULL, true);

	/* trusted procedure invocation */
	finfo->sepgsql_addr = finfo->fn_addr;
	finfo->fn_addr = sepgsqlTrustedProcInvoker;
	finfo->sepgsql_label = newcon;

	MemoryContextSwitchTo(oldctx);
}

/*
 * sepgsqlCheckFileRead
 * sepgsqlCheckFileWrite
 *
 *   These functions check file:{read} or file:{write} permission on
 *   the given file descriptor
 */
static void
checkFileReadWrite(int fdesc, const char *filename, bool is_read)
{
	security_context_t	context;
	security_class_t	tclass;

	if (!sepgsqlIsEnabled())
		return;

	tclass = sepgsqlFileObjectClass(fdesc);

	if (fgetfilecon_raw(fdesc, &context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get context of %s", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(sepgsqlGetClientLabel(),
							context,
							tclass,
							is_read ? SEPG_FILE__READ : SEPG_FILE__WRITE,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
}

void
sepgsqlCheckFileRead(int fdesc, const char *filename)
{
	checkFileReadWrite(fdesc, filename, true);
}

void
sepgsqlCheckFileWrite(int fdesc, const char *filename)
{
	checkFileReadWrite(fdesc, filename, false);
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
	sepgsql_sid_t		prosid;

	if (!sepgsqlIsEnabled())
		return true;

	prosid = HeapTupleGetSecLabel(ProcedureRelationId, proc_tuple);
	context = sepgsqlClientCreateLabel(prosid,
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
