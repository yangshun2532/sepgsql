/*
 * src/backend/utils/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * sepgsqlDatabaseAccess
 *   checks db_database:{access} permission when a client logged in
 *   a specific database.
 *   pg_database_aclcheck() invokes this function.
 */
bool sepgsqlCheckDatabaseAccess(Oid db_oid)
{
	const char *audit_name;
	HeapTuple tuple;
	bool rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(db_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database: %u", db_oid);

	audit_name = sepgsqlAuditName(DatabaseRelationId, tuple);
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_DATABASE,
							   DB_DATABASE__ACCESS,
							   audit_name, false);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsqlDatabaseGetParam
 *   checks db_database:{get_param} permission
 */
void
sepgsqlCheckDatabaseGetParam(const char *name)
{
	const char *audit_name;
	HeapTuple   tuple;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u",
			 MyDatabaseId);

	audit_name = sepgsqlAuditName(DatabaseRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SECCLASS_DB_DATABASE,
						  DB_DATABASE__GET_PARAM,
						  audit_name, true);
	ReleaseSysCache(tuple);
}

/*
 * sepgsqlDatabaseSetParam
 *   checks db_database:{set_param} permission
 */
void
sepgsqlCheckDatabaseSetParam(const char *name)
{
	const char *audit_name;
	HeapTuple   tuple;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u",
			 MyDatabaseId);

	audit_name = sepgsqlAuditName(DatabaseRelationId, tuple);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
						  SECCLASS_DB_DATABASE,
						  DB_DATABASE__SET_PARAM,
						  audit_name, true);
	ReleaseSysCache(tuple);
}

/*
 * sepgsqlDatabaseInstallModule
 *   checks db_database:{install_module} permission on
 *   the current database and a given loadable module.
 */
void
sepgsqlCheckDatabaseInstallModule(const char *filename)
{
	security_context_t fcontext;
	HeapTuple tuple;
	const char *audit_name;
	char *fullpath;

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
						  SECCLASS_DB_DATABASE,
						  DB_DATABASE__INSTALL_MODULE,
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
							SECCLASS_DB_DATABASE,
							DB_DATABASE__INSTALL_MODULE,
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
							SECCLASS_DB_DATABASE,
							DB_DATABASE__LOAD_MODULE,
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
 * sepgsqlTableLock
 *   checks db_table:{lock} permission for explicit table lock
 */
bool
sepgsqlCheckTableLock(Oid relid)
{
	const char	   *audit_name;
	Form_pg_class	classForm;
	HeapTuple		tuple;
	bool			rc = true;

	if (!sepgsqlIsEnabled())
		return true;

	/*
	 * check db_table:{lock} permission
	 */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	classForm = (Form_pg_class) GETSTRUCT(tuple);
	if (classForm->relkind == RELKIND_RELATION)
	{
		audit_name = sepgsqlAuditName(RelationRelationId, tuple);
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
								   SECCLASS_DB_TABLE,
								   DB_TABLE__LOCK,
								   audit_name, false);
	}
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsqlTableTruncate
 *   checks db_table:{delete} permission
 */
bool
sepgsqlCheckTableTruncate(Relation rel)
{
	const char *audit_name;
	HeapTuple	tuple;
	HeapScanDesc	scan;
	bool		rc;

	if (!sepgsqlIsEnabled())
		return true;

	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	/*
	 * check db_table:{delete} permission
	 */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(RelationGetRelid(rel)),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation: %s",
			 RelationGetRelationName(rel));

	audit_name = sepgsqlAuditName(RelationRelationId, tuple);
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_TABLE,
							   DB_TABLE__DELETE,
							   audit_name, false);
	ReleaseSysCache(tuple);

	/*
	 * check db_tuple:{delete} permission on whole of the table
	 */
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		rc = sepgsqlCheckObjectPerms(rel, tuple, NULL,
									 SEPGSQL_PERMS_DELETE, false);
		if (!rc)
			break;
	}
	heap_endscan(scan);

	return rc;
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
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
							   SECCLASS_DB_PROCEDURE,
							   DB_PROCEDURE__EXECUTE,
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
	security_context_t	newcon;
	const char		   *audit_name;

	if (!sepgsqlIsEnabled())
		return;
	/*
	 * NOTE: built-in trusted procedure is not supported currently,
	 * because SearchSysCache(PROCOID, ...) invokes another built-in
	 * function to fetch a tuple from system catalog, then it makes
	 * infinite function invocation.
	 * It can be fixed later.
	 */
	if (!HeapTupleIsValid(protup))
		return;

	oldctx = MemoryContextSwitchTo(finfo->fn_mcxt);

	newcon = sepgsqlClientCreateLabel(HeapTupleGetSecLabel(protup),
									  SECCLASS_PROCESS);
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
	{
		MemoryContextSwitchTo(oldctx);
		return;
	}
	/* db_procedure:{entrypoint} */
	audit_name = sepgsqlAuditName(ProcedureRelationId, protup);
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(protup),
						  SECCLASS_DB_PROCEDURE,
						  DB_PROCEDURE__ENTRYPOINT,
						  audit_name, true);

	/* process:{transition} */
	sepgsqlComputePerms(sepgsqlGetClientLabel(),
						newcon,
						SECCLASS_PROCESS,
						PROCESS__TRANSITION,
						NULL, true);

	/* trusted procedure invocation */
	finfo->sepgsql_addr = finfo->fn_addr;
	finfo->fn_addr = sepgsqlTrustedProcInvoker;
	finfo->sepgsql_label = newcon;

	MemoryContextSwitchTo(oldctx);
}

/*
 * sepgsqlCheckTupleSelectOnTrigger
 *   checks db_tuple:{select} permission on fetched tuple
 *   on per-tuple trigger
 */
bool
sepgsqlCheckTupleSelectOnTrigger(TriggerData *tgdata)
{
	Relation	rel = tgdata->tg_relation;
	HeapTuple	newtup = NULL;
	HeapTuple	oldtup = NULL;

	/* no need to check for statement triggers */
	if (TRIGGER_FIRED_FOR_STATEMENT(tgdata->tg_event))
		return true;

	if (TRIGGER_FIRED_BY_INSERT(tgdata->tg_event))
	{
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
			newtup = tgdata->tg_trigtuple;
	}
	else if (TRIGGER_FIRED_BY_UPDATE(tgdata->tg_event))
	{
		oldtup = tgdata->tg_trigtuple;
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
		{
			sepgsql_sid_t	sid = HeapTupleGetSecLabel(oldtup);
			if (HeapTupleGetSecLabel(tgdata->tg_newtuple) != sid)
				newtup = tgdata->tg_newtuple;
		}
	}
	else if (TRIGGER_FIRED_BY_DELETE(tgdata->tg_event))
	{
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
			oldtup = tgdata->tg_trigtuple;
	}
	else
	{
		elog(ERROR, "SELinux: unexpected trigger event: %u",
			 tgdata->tg_event);
	}

	if (HeapTupleIsValid(oldtup) &&
		!sepgsqlCheckObjectPerms(rel, oldtup, NULL,
								 SEPGSQL_PERMS_SELECT, false))
		return false;

	if (HeapTupleIsValid(newtup) &&
		!sepgsqlCheckObjectPerms(rel, newtup, NULL,
								 SEPGSQL_PERMS_SELECT, false))
		return false;

	return true;
}

/*
 * 
 */
static bool
IsTrustedAction(Relation rel, bool internal)
{
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	if (internal &&
		(RelationGetRelid(rel) == SecurityRelationId ||
		 RelationGetRelid(rel) == LargeObjectRelationId))
		return true;

	return false;
}

/*
 * Row-level decision making
 */
bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, AclMode required, bool abort)
{
	Assert((required & SEPGSQL_PERMS_MASK) == required);

	if (IsTrustedAction(rel, false))
		return true;

	return sepgsqlCheckObjectPerms(rel, tuple, NULL, required, abort);
}

/*
 * HeapTuple INSERT/UPDATE/DELETE
 */
bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	uint32		perms = SEPGSQL_PERMS_INSERT;

	if (!sepgsqlIsEnabled())
		return true;

	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		/*
		 * When no explicit security label is given,
		 * it assigns a default one.
		 */
		if (HeapTupleHasSecLabel(newtup))
			sepgsqlSetDefaultSecLabel(rel, newtup);
	}

	if (IsTrustedAction(rel, internal))
		return true;

	return sepgsqlCheckObjectPerms(rel, newtup, NULL, perms, internal);
}

bool
sepgsqlHeapTupleUpdate(Relation rel, HeapTuple oldtup,
					   HeapTuple newtup, bool internal)
{
	Oid				relid = RelationGetRelid(rel);
	uint32			perms = SEPGSQL_PERMS_UPDATE;
	bool			rc;

	if (!sepgsqlIsEnabled())
		return true;

	if (!OidIsValid(HeapTupleGetSecLabel(newtup)))
	{
		/*
		 * When no explicit security label is given,
		 * it preserves an older security label.
		 */
		sepgsql_sid_t	oldsid = HeapTupleGetSecLabel(oldtup);

		if (HeapTupleHasSecLabel(newtup))
			HeapTupleSetSecLabel(newtup, oldsid);
	}

	if (IsTrustedAction(rel, internal))
		return true;

	if (HeapTupleGetSecLabel(oldtup) != HeapTupleGetSecLabel(newtup) ||
		sepgsqlTupleObjectClass(relid, newtup)
			!= sepgsqlTupleObjectClass(relid, oldtup))
		perms |= SEPGSQL_PERMS_RELABELFROM;

	rc = sepgsqlCheckObjectPerms(rel, oldtup, newtup, perms, internal);

	if (rc && perms & SEPGSQL_PERMS_RELABELFROM)
	{
		perms = SEPGSQL_PERMS_RELABELTO;
		rc = sepgsqlCheckObjectPerms(rel, newtup, NULL, perms, internal);
	}

	return rc;
}

bool
sepgsqlHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal)
{
	uint32		perms = SEPGSQL_PERMS_DELETE;
	bool		rc;

	if (!sepgsqlIsEnabled())
		return true;

	if (IsTrustedAction(rel, internal))
		return true;

	rc = sepgsqlCheckObjectPerms(rel, oldtup, NULL, perms, internal);

	return rc;
}

/*
 * sepgsqlCopyTable
 *
 * This function checks permission on the target table and columns
 * of COPY statement. We don't place it at sepgsql/hooks.c because
 * it internally uses addEvalXXXX() interface statically declared.
 */
void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom)
{
	List	   *selist = NIL;
	ListCell   *l;

	if (!sepgsqlIsEnabled())
		return;

	/*
	 * on 'COPY FROM SELECT ...' cases, any checkings are done in select.c
	 */
	if (rel == NULL)
		return;

	/*
	 * no need to check non-table relation
	 */
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return;

	selist = sepgsqlAddEvalTable(selist, RelationGetRelid(rel), false,
								 isFrom ? DB_TABLE__INSERT : DB_TABLE__SELECT);
	foreach(l, attNumList)
	{
		AttrNumber	attnum = lfirst_int(l);

		selist = sepgsqlAddEvalColumn(selist, RelationGetRelid(rel), false, attnum,
									  isFrom ? DB_COLUMN__INSERT : DB_COLUMN__SELECT);
	}

	/*
	 * check call trigger function
	 */
	if (isFrom)
		selist = sepgsqlAddEvalTriggerFunc(selist, RelationGetRelid(rel), CMD_INSERT);

	foreach (l, selist)
		sepgsqlCheckSelinuxEvalItem((SelinuxEvalItem *) lfirst(l));
}

/*
 * sepgsqlCopyFile
 *
 * This function check permission whether the client can
 * read from/write to the given file.
 */
void sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom)
{
	security_context_t context;
	security_class_t tclass;

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
							isFrom ? FILE__READ : FILE__WRITE,
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

bool
sepgsqlCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	uint32		perms = SEPGSQL_PERMS_SELECT;

	return sepgsqlCheckObjectPerms(rel, tuple, NULL, perms, false);
}

/*
 * checkBlobCommon
 *   a common facility to check permission on blob
 */
static void
checkBlobCommon(Oid loid, Oid secid, access_vector_t required)
{
	char	audit_name[64];

	snprintf(audit_name, sizeof(audit_name), "blob:%u", loid);

	sepgsqlClientHasPerms(secid, SECCLASS_DB_BLOB,
						  required, audit_name, true);
}

/*
 * sepgsqlCheckBlobDrop
 *   checks db_blob:{drop} permission
 */
void
sepgsqlCheckBlobDrop(HeapTuple lotup)
{
	Form_pg_largeobject	loForm
		= (Form_pg_largeobject) GETSTRUCT(lotup);

	if (sepgsqlIsEnabled())
		checkBlobCommon(loForm->loid,
						HeapTupleGetSecLabel(lotup),
						DB_BLOB__DROP);
}

/*
 * sepgsqlCheckBlobRead
 *   checks db_blob:{read} permission
 */
void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj)
{
	if (sepgsqlIsEnabled())
		checkBlobCommon(lobj->id, lobj->secid, DB_BLOB__READ);
}

/*
 * sepgsqlCheckBlobWrite
 *   check db_blob:{write} permission
 */
void
sepgsqlCheckBlobWrite(LargeObjectDesc *lobj)
{
	if (sepgsqlIsEnabled())
		checkBlobCommon(lobj->id, lobj->secid, DB_BLOB__WRITE);
}

/*
 * sepgsqlCheckBlobGetattr
 *   check db_blob:{getattr} permission
 */
void
sepgsqlCheckBlobGetattr(LargeObjectDesc *lobj)
{
	if (sepgsqlIsEnabled())
		checkBlobCommon(lobj->id, lobj->secid, DB_BLOB__GETATTR);
}

/*
 * sepgsqlCheckBlobSetattr
 *   check db_blob:{setattr} permission
 */
void
sepgsqlCheckBlobSetattr(LargeObjectDesc *lobj)
{
	if (sepgsqlIsEnabled())
		checkBlobCommon(lobj->id, lobj->secid, DB_BLOB__SETATTR);
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

	if (!sepgsqlIsEnabled())
		return;

	checkBlobCommon(lobj->id, lobj->secid,
					DB_BLOB__READ | DB_BLOB__EXPORT);

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
							COMMON_FILE__WRITE,
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

	if (!sepgsqlIsEnabled())
		return;

	checkBlobCommon(lobj->id, lobj->secid,
					DB_BLOB__WRITE | DB_BLOB__IMPORT);

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
							COMMON_FILE__READ,
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
	access_vector_t		required = DB_BLOB__SETATTR;
	Form_pg_largeobject	loForm;

	if (HeapTupleGetSecLabel(oldtup) != HeapTupleGetSecLabel(newtup))
		required |= DB_BLOB__RELABELFROM;

	loForm = (Form_pg_largeobject) GETSTRUCT(oldtup);
	checkBlobCommon(loForm->loid, HeapTupleGetSecLabel(oldtup), required);

	if ((required & DB_BLOB__RELABELFROM) == 0)
		return;

	loForm = (Form_pg_largeobject) GETSTRUCT(newtup);
	checkBlobCommon(loForm->loid, HeapTupleGetSecLabel(newtup),
					DB_BLOB__RELABELTO);
}
