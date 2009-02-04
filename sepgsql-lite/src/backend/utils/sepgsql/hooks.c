/*
 * src/backend/utils/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "storage/bufmgr.h"
#include "utils/sepgsql.h"
#include "utils/syscache.h"

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
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(DatabaseRelationId, tuple),
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
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(DatabaseRelationId, tuple),
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
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(DatabaseRelationId, tuple),
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
	sepgsqlClientHasPerms(HeapTupleGetSecLabel(DatabaseRelationId, tuple),
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
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(RelationRelationId, tuple),
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
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(RelationRelationId, tuple),
							   SECCLASS_DB_TABLE,
							   DB_TABLE__DELETE,
							   audit_name, false);
	ReleaseSysCache(tuple);

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
	rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(ProcedureRelationId, tuple),
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
	sepgsql_sid_t		prosid;
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

	newcon = sepgsqlClientCreateLabel(HeapTupleGetSecLabel(ProcedureRelationId, protup),
									  SECCLASS_PROCESS);
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
	{
		MemoryContextSwitchTo(oldctx);
		return;
	}
	/* db_procedure:{entrypoint} */
	audit_name = sepgsqlAuditName(ProcedureRelationId, protup);
	prosid = HeapTupleGetSecLabel(ProcedureRelationId, protup);
	sepgsqlClientHasPerms(prosid,
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
 * HeapTuple INSERT/UPDATE/DELETE
 */
static HeapTuple
getHeapTupleFromItemPointer(Relation rel, ItemPointer tid)
{
	Buffer			buffer;
	PageHeader		dp;
	ItemId			lp;
	HeapTupleData	tuple;
	HeapTuple		oldtup;

	buffer = ReadBuffer(rel, ItemPointerGetBlockNumber(tid));
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = (PageHeader) BufferGetPage(buffer);
	lp = PageGetItemId(dp, ItemPointerGetOffsetNumber(tid));

	Assert(ItemIdIsNormal(lp));

	tuple.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_self = *tid;
	tuple.t_tableOid = RelationGetRelid(rel);
	oldtup = heap_copytuple(&tuple);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	ReleaseBuffer(buffer);

	return oldtup;
}

HeapTuple
sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple, bool internal)
{
	uint32 perms = SEPGSQL_PERMS_INSERT;

	if (!sepgsqlIsEnabled())
		return tuple;

	/*
	 * Set a default security context, if unlabeled
	 */
	if (HeapTupleHasSecLabel(RelationGetRelid(rel), tuple) &&
		!HeapTupleGetSecLabel(RelationGetRelid(rel), tuple))
	{
		Datum  *values;
		bool   *nulls;
		int		natts = RelationGetNumberOfAttributes(rel);

		Assert(!internal);

		values = (Datum *) palloc(natts * sizeof(Datum));
		nulls = (bool *) palloc(natts * sizeof(bool));

		heap_deform_tuple(tuple, RelationGetDescr(rel), values, nulls);
		sepgsqlSetDefaultSecLabel(RelationGetRelid(rel),
								  values, nulls, PointerGetDatum(NULL));
		tuple = heap_form_tuple(RelationGetDescr(rel), values, nulls);
	}

	sepgsqlCheckObjectPerms(rel, tuple, NULL, perms, true);

	return tuple;
}

void
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid,
					   HeapTuple newtup, bool internal)
{
	Oid				relid = RelationGetRelid(rel);
	HeapTuple		oldtup;
	sepgsql_sid_t	newsid;
	sepgsql_sid_t	oldsid;
	uint32			perms;

	if (!sepgsqlIsEnabled())
		return;

	oldtup = getHeapTupleFromItemPointer(rel, otid);

	newsid = HeapTupleGetSecLabel(RelationGetRelid(rel), newtup);
	oldsid = HeapTupleGetSecLabel(RelationGetRelid(rel), oldtup);

	perms = SEPGSQL_PERMS_UPDATE;
	if ((oldsid == NULL && newsid != NULL) ||
		(oldsid != NULL && newsid == NULL) ||
		(oldsid != NULL && newsid != NULL && strcmp(oldsid, newsid) != 0) ||
		(sepgsqlTupleObjectClass(relid, newtup)
			!= sepgsqlTupleObjectClass(relid, oldtup)))
		perms |= SEPGSQL_PERMS_RELABELFROM;

	sepgsqlCheckObjectPerms(rel, oldtup, newtup, perms, true);

	if (perms & SEPGSQL_PERMS_RELABELFROM)
	{
		perms = SEPGSQL_PERMS_RELABELTO;
		sepgsqlCheckObjectPerms(rel, newtup, NULL, perms, true);
	}
	heap_freetuple(oldtup);
}

void
sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid, bool internal)
{
	HeapTuple	oldtup;
	uint32		perms;

	if (!sepgsqlIsEnabled())
		return;

	oldtup = getHeapTupleFromItemPointer(rel, otid);
	perms = SEPGSQL_PERMS_DELETE;

	sepgsqlCheckObjectPerms(rel, oldtup, NULL, perms, true);

	heap_freetuple(oldtup);
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
