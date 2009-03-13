/*
 * src/backend/security/sepgsql/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_amproc.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
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
 * sepgsqlDatabaseInstallModule
 *   checks db_database:{install_module} permission on
 *   the current database and a given loadable module.
 */
void
sepgsqlCheckDatabaseInstallModule(const char *filename)
{
	security_context_t	fcontext;
	HeapTuple			tuple;
	const char		   *audit_name;
	char			   *fullpath;

	if (!sepgsqlIsEnabled())
		return;

	/* (client) <-- db_database:module_install --> (database) */
	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u",
			 MyDatabaseId);

	audit_name = sepgsqlAuditName(DatabaseRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__INSTALL_MODULE,
						  audit_name, true);
	ReleaseSysCache(tuple);

	/* (client) <-- db_databse:module_install --> (*.so file) */
	fullpath = expand_dynamic_library_name(filename);
	if (getfilecon_raw(fullpath, &fcontext) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not access file \"%s\": %m", fullpath)));
	PG_TRY();
	{
		sepgsqlComputePerms(sepgsqlGetClientLabel(),
							fcontext,
							SEPG_CLASS_DB_DATABASE,
							SEPG_DB_DATABASE__INSTALL_MODULE,
							fullpath, true);
	}
	PG_CATCH();
	{
		freecon(fcontext);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(fcontext);
}

/*
 * sepgsqlDatabaseLoadModule
 *   checks capability of database to load a specific library
 */
void
sepgsqlCheckDatabaseLoadModule(const char *filename)
{
	security_context_t filecon;

	if (!sepgsqlIsEnabled())
		return;

	if (getfilecon_raw(filename, &filecon) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not access file \"%s\": %m", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(sepgsqlGetDatabaseLabel(),
							filecon,
							SEPG_CLASS_DB_DATABASE,
							SEPG_DB_DATABASE__LOAD_MODULE,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(filecon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(filecon);
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
static bool
checkTableCommon(Oid table_oid, access_vector_t perms)
{
	const char		   *audit_name;
	security_class_t	tclass;
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
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
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
	HeapScanDesc	scan;
	HeapTuple		tuple;
	const char	   *audit_name;
	bool			rc = true;

	if (!checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE))
		return false;

	/*
	 * check db_tuple:{delete} permission
	 */
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		audit_name = sepgsqlAuditName(RelationGetRelid(rel), tuple);
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
								   SEPG_CLASS_DB_TABLE,
								   SEPG_DB_TUPLE__DELETE,
								   audit_name, false);
		if (!rc)
			break;
	}
	heap_endscan(scan);

	return rc;
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

	newcon = sepgsqlClientCreateLabel(HeapTupleGetSecLabel(protup),
									  SEPG_CLASS_PROCESS);
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
	{
		MemoryContextSwitchTo(oldctx);
		return;
	}
	/* db_procedure:{entrypoint}, if trusted procedure */
	audit_name = sepgsqlAuditName(ProcedureRelationId, protup);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(protup),
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
 * sepgsqlCheckProcedureInstall
 *   checks permission: db_procedure:{install}, when client tries to modify
 *   a system catalog which contains procedure id to invoke it later.
 *   Because these functions are invoked internally, to search a table with
 *   a special index algorithm for example, the security policy has to prevent
 *   malicious user-defined functions to be installed.
 */
static void
checkProcedureInstall(Oid proc_oid)
{
	sepgsql_sid_t	prosid;
    HeapTuple		protup = NULL;
    const char	   *audit_name = NULL;

	if (!OidIsValid(proc_oid))
		return;

	if (IsBootstrapProcessingMode())
	{
		/*
		 * Assumption: security label is unchanged
		 * during bootstraptin mode, because no one
		 * tries to relabel anything.
		 */
		prosid  = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
									  SEPG_CLASS_DB_PROCEDURE);
	}
	else
	{
		protup = SearchSysCache(PROCOID,
								ObjectIdGetDatum(proc_oid),
								0, 0, 0);
		if (!HeapTupleIsValid(protup))
			return;

		audit_name = sepgsqlAuditName(ProcedureRelationId, protup);
		prosid = HeapTupleGetSecLabel(protup);
	}

	sepgsqlClientHasPerms(prosid,
						  SEPG_CLASS_DB_PROCEDURE,
						  SEPG_DB_PROCEDURE__INSTALL,
						  audit_name, true);
	if (HeapTupleIsValid(protup))
		ReleaseSysCache(protup);
}

#define CHECK_PROC_INSTALL_PERM(catalog,member,newtup,oldtup)			\
	do {																\
		if (!HeapTupleIsValid(oldtup))                                  \
			checkProcedureInstall(((Form_##catalog) GETSTRUCT(newtup))->member); \
		else if (((Form_##catalog) GETSTRUCT(newtup))->member           \
				 != ((Form_##catalog) GETSTRUCT(oldtup))->member)       \
			checkProcedureInstall(((Form_##catalog) GETSTRUCT(newtup))->member); \
	} while(0)

void
sepgsqlCheckProcedureInstall(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	/*
	 * db_procedure:{install} check prevent a malicious functions
	 * to be installed, as a part of system catalogs.
	 * It is necessary to prevent other person implicitly to invoke
	 * malicious functions.
	 */
	switch (RelationGetRelid(rel))
	{
	case AggregateRelationId:
		/*
		 * db_procedure:{execute} is checked on invocations of:
		 *   pg_aggregate.aggfnoid
		 *   pg_aggregate.aggtransfn
		 *   pg_aggregate.aggfinalfn
		 */
		break;

	case AccessMethodRelationId:
		CHECK_PROC_INSTALL_PERM(pg_am, aminsert, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambeginscan, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amgettuple, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amgetmulti, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amrescan, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amendscan, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ammarkpos, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amrestrpos, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambuild, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambulkdelete, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amvacuumcleanup, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amcostestimate, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amoptions, newtup, oldtup);
		break;

	case AccessMethodProcedureRelationId:
		CHECK_PROC_INSTALL_PERM(pg_amproc, amproc, newtup, oldtup);
		break;

	case CastRelationId:
		CHECK_PROC_INSTALL_PERM(pg_cast, castfunc, newtup, oldtup);
		break;

	case ConversionRelationId:
		CHECK_PROC_INSTALL_PERM(pg_conversion, conproc, newtup, oldtup);
		break;

	case LanguageRelationId:
		CHECK_PROC_INSTALL_PERM(pg_language, lanplcallfoid, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_language, lanvalidator, newtup, oldtup);
		break;

	case OperatorRelationId:
		CHECK_PROC_INSTALL_PERM(pg_operator, oprcode, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_operator, oprrest, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_operator, oprjoin, newtup, oldtup);
		break;

	case TriggerRelationId:
		CHECK_PROC_INSTALL_PERM(pg_trigger, tgfoid, newtup, oldtup);
		break;

	case TSParserRelationId:
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsstart, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prstoken, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsend, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsheadline, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prslextype, newtup, oldtup);
		break;

	case TSTemplateRelationId:
		CHECK_PROC_INSTALL_PERM(pg_ts_template, tmplinit, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_template, tmpllexize, newtup, oldtup);
		break;

	case TypeRelationId:
		CHECK_PROC_INSTALL_PERM(pg_type, typinput, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typoutput, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typreceive, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typsend, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typmodin, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typmodout, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typanalyze, newtup, oldtup);
		break;
	}
}

/*
 * sepgsqlCheckBlobDrop
 *   checks db_blob:{drop} permission
 */
void
sepgsqlCheckBlobDrop(HeapTuple lotup)
{
	const char	   *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	audit_name = sepgsqlAuditName(LargeObjectRelationId, lotup);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(lotup),
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__DROP,
						  audit_name, true);
}

/*
 * sepgsqlCheckBlobRead
 *   checks db_blob:{read} permission
 */
void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj)
{
	char	audit_name[NAMEDATALEN];

	if (!sepgsqlIsEnabled())
		return;

	snprintf(audit_name, sizeof(audit_name), "blob:%u", lobj->id);
	sepgsqlClientHasPerms(lobj->secid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__READ,
						  audit_name, true);
}

/*
 * sepgsqlCheckBlobWrite
 *   check db_blob:{write} permission
 */
void
sepgsqlCheckBlobWrite(LargeObjectDesc *lobj)
{
	char	audit_name[NAMEDATALEN];

	if (!sepgsqlIsEnabled())
		return;

	snprintf(audit_name, sizeof(audit_name), "blob:%u", lobj->id);
	sepgsqlClientHasPerms(lobj->secid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__WRITE,
						  audit_name, true);
}

/*
 * sepgsqlCheckBlobGetattr
 *   check db_blob:{getattr} permission
 */
void
sepgsqlCheckBlobGetattr(HeapTuple tuple)
{
	const char	   *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	audit_name = sepgsqlAuditName(LargeObjectRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__GETATTR,
						  audit_name, true);
}

/*
 * sepgsqlCheckBlobSetattr
 *   check db_blob:{setattr} permission
 */
void
sepgsqlCheckBlobSetattr(HeapTuple tuple)
{
	const char	   *audit_name;

	if (!sepgsqlIsEnabled())
		return;

	audit_name = sepgsqlAuditName(LargeObjectRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__SETATTR,
						  audit_name, true);
}

/*
 * sepgsqlCheckBlobExport
 *   check db_blob:{read export} and file:{write} permission
 */
void
sepgsqlCheckBlobExport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename)
{
	security_context_t		fcontext;
	security_class_t		fclass;
	char					audit_name[NAMEDATALEN];

	if (!sepgsqlIsEnabled())
		return;

	snprintf(audit_name, sizeof(audit_name), "blob:%u", lobj->id);
	sepgsqlClientHasPerms(lobj->secid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__READ | SEPG_DB_BLOB__EXPORT,
						  audit_name, true);

	fclass = sepgsqlFileObjectClass(fdesc);
	if (fgetfilecon_raw(fdesc, &fcontext) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not get security context \"%s\"", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(sepgsqlGetClientLabel(),
							fcontext,
							fclass,
							SEPG_FILE__WRITE,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(fcontext);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(fcontext);
}

/*
 * sepgsqlCheckBlobImport
 *   check db_blob:{write import} and file:{read} permission
 */
void
sepgsqlCheckBlobImport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename)
{
	security_context_t		fcontext;
	security_class_t		fclass;
	char					audit_name[NAMEDATALEN];

	if (!sepgsqlIsEnabled())
		return;

	snprintf(audit_name, sizeof(audit_name), "blob:%u", lobj->id);
	sepgsqlClientHasPerms(lobj->secid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__WRITE | SEPG_DB_BLOB__IMPORT,
						  audit_name, true);

	fclass = sepgsqlFileObjectClass(fdesc);
	if (fgetfilecon_raw(fdesc, &fcontext) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not get security context \"%s\"", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(sepgsqlGetClientLabel(),
							fcontext,
							fclass,
							SEPG_FILE__READ,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(fcontext);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(fcontext);
}

/*
 * sepgsqlCheckBlobRelabel
 *   check db_blob:{setattr relabelfrom relabelto}
 */
void
sepgsqlCheckBlobRelabel(HeapTuple oldtup, HeapTuple newtup)
{
	access_vector_t		required = SEPG_DB_BLOB__SETATTR;
	const char		   *audit_name;

	if (HeapTupleGetSecLabel(oldtup) != HeapTupleGetSecLabel(newtup))
		required |= SEPG_DB_BLOB__RELABELFROM;

	audit_name = sepgsqlAuditName(LargeObjectRelationId, oldtup);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(oldtup),
						  SEPG_CLASS_DB_BLOB,
						  required,
						  audit_name, true);
	if ((required & SEPG_DB_BLOB__RELABELFROM) == 0)
		return;

	audit_name = sepgsqlAuditName(LargeObjectRelationId, newtup);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(newtup),
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__RELABELTO,
						  audit_name, true);
}

/*
 * sepgsqlCheckFileRead
 * sepgsqlCheckFileWrite
 *   check file:{read} or file:{write} permission on the given file,
 *   and raises an error if violated.
 */
static void
checkFileCommon(int fdesc, const char *filename, access_vector_t perms)
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
							perms,
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
	checkFileCommon(fdesc, filename, SEPG_FILE__READ);
}

void
sepgsqlCheckFileWrite(int fdesc, const char *filename)
{
	checkFileCommon(fdesc, filename, SEPG_FILE__WRITE);
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
