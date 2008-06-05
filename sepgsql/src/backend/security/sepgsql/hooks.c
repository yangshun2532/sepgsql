/*
 * src/backend/sepgsqlHooks.c
 *   SE-PostgreSQL hooks
 *
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/genam.h"
#include "access/skey.h"
#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/pgace.h"
#include "security/sepgsql.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "utils/tqual.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

/*******************************************************************************
 * Extended SQL statement hooks
 *******************************************************************************/
DefElem *sepgsqlGramSecurityItem(char *defname, char *value)
{
	DefElem *n = NULL;
	if (!strcmp(defname, "context"))
		n = makeDefElem(pstrdup(defname), (Node *) makeString(value));
	return n;
}

bool sepgsqlIsGramSecurityItem(DefElem *defel)
{
	Assert(IsA(defel, DefElem));
	if (defel->defname && !strcmp(defel->defname, "context"))
		return true;
	return false;
}

static void putExplicitContext(HeapTuple tuple, DefElem *defel)
{
	if (defel)
	{
		Oid security_id = pgaceSecurityLabelToSid(strVal(defel->arg));

		HeapTupleSetSecurity(tuple, security_id);
	}
}

void sepgsqlGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void sepgsqlGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void sepgsqlGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void sepgsqlGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void sepgsqlGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void sepgsqlGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void sepgsqlGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

void sepgsqlGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	putExplicitContext(tuple, defel);
}

/*******************************************************************************
 * DATABASE object related hooks
 *******************************************************************************/

void sepgsqlGetDatabaseParam(const char *name)
{
	Form_pg_database dbForm;
	security_context_t dbcon;
	HeapTuple tuple;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u", MyDatabaseId);

	dbForm = (Form_pg_database) GETSTRUCT(tuple);

	dbcon = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));

	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 dbcon,
						 SECCLASS_DB_DATABASE,
						 DB_DATABASE__GET_PARAM,
						 NameStr(dbForm->datname));
	ReleaseSysCache(tuple);
}

void sepgsqlSetDatabaseParam(const char *name, char *argstring)
{
	Form_pg_database dbForm;
	security_context_t dbcon;
	HeapTuple tuple;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for database %u", MyDatabaseId);

	dbForm = (Form_pg_database) GETSTRUCT(tuple);

	dbcon = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));

	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 dbcon,
						 SECCLASS_DB_DATABASE,
						 DB_DATABASE__GET_PARAM,
						 NameStr(dbForm->datname));
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * RELATION(Table)/ATTRIBTUE(column) object related hooks
 *******************************************************************************/
void sepgsqlLockTable(Oid relid)
{
	Form_pg_class clsForm;
	security_context_t tblcon;
	HeapTuple tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);
	clsForm = (Form_pg_class) GETSTRUCT(tuple);

	tblcon = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));

	if (clsForm->relkind == RELKIND_RELATION)
	{
		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 tblcon,
							 SECCLASS_DB_TABLE,
							 DB_TABLE__LOCK,
							 NameStr(clsForm->relname));
	}
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * PROCEDURE related hooks
 *******************************************************************************/

static Datum invokeTrustedProcedure(PG_FUNCTION_ARGS)
{
	security_context_t orig_context, new_context;
	Datum retval;

	/* set new domain */
	new_context = DatumGetCString(fcinfo->flinfo->fn_pgace_data);
	orig_context = sepgsqlSwitchClientContext(new_context);

	PG_TRY();
	{
		retval = fcinfo->flinfo->fn_pgace_addr(fcinfo);
	}
	PG_CATCH();
	{
		sepgsqlSwitchClientContext(orig_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	sepgsqlSwitchClientContext(orig_context);

	return retval;
}

void sepgsqlCallFunction(FmgrInfo *finfo, bool with_perm_check)
{
	MemoryContext oldctx;
	Form_pg_proc proForm;
	HeapTuple tuple;
	security_context_t procon, newcon;
	access_vector_t perms = DB_PROCEDURE__EXECUTE;

	oldctx = MemoryContextSwitchTo(finfo->fn_mcxt);

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(finfo->fn_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure %u", finfo->fn_oid);
	proForm = (Form_pg_proc) GETSTRUCT(tuple);

	/* check trusted procedure */
	procon = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));

	newcon = sepgsqlAvcCreateCon(sepgsqlGetClientContext(),
								 procon,
								 SECCLASS_PROCESS);

	if (strcmp(newcon, sepgsqlGetClientContext()))
	{
		finfo->fn_pgace_addr = finfo->fn_addr;
		finfo->fn_pgace_data = CStringGetDatum(newcon);
		finfo->fn_addr = invokeTrustedProcedure;

		perms |= DB_PROCEDURE__ENTRYPOINT;
	}

	if (with_perm_check)
	{
		/* check procedure:{execute entrypoint} permission */
		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 procon,
							 SECCLASS_DB_PROCEDURE,
							 perms,
							 NameStr(proForm->proname));
	}

	ReleaseSysCache(tuple);

	MemoryContextSwitchTo(oldctx);
}

bool sepgsqlCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata)
{
	Relation rel = tgdata->tg_relation;
	HeapTuple newtup = NULL;
	HeapTuple oldtup = NULL;

	if (TRIGGER_FIRED_FOR_STATEMENT(tgdata->tg_event))
		return true;  /* statement trigger does not contain any tuple */
	if (TRIGGER_FIRED_BY_INSERT(tgdata->tg_event)) {
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
			newtup = tgdata->tg_trigtuple;
	} else if (TRIGGER_FIRED_BY_UPDATE(tgdata->tg_event)) {
		oldtup = tgdata->tg_trigtuple;
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event)
			&& HeapTupleGetSecurity(oldtup) != HeapTupleGetSecurity(tgdata->tg_newtuple))
			newtup = tgdata->tg_newtuple;
	} else if (TRIGGER_FIRED_BY_DELETE(tgdata->tg_event)) {
		if (TRIGGER_FIRED_AFTER(tgdata->tg_event))
			oldtup = tgdata->tg_trigtuple;
	} else {
		elog(ERROR, "SELinux: unexpected trigger event type (%u)", tgdata->tg_event);
	}
	if (oldtup && !sepgsqlCheckTuplePerms(rel, oldtup, NULL, SEPGSQL_PERMS_SELECT, false))
		return false;
	if (newtup && !sepgsqlCheckTuplePerms(rel, newtup, NULL, SEPGSQL_PERMS_SELECT, false))
		return false;

	sepgsqlCallFunction(finfo, false);

	return true;
}

/*******************************************************************************
 * LOAD shared library module hook
 *******************************************************************************/
void sepgsqlLoadSharedModule(const char *filename)
{
	security_context_t filecon;

	if (getfilecon_raw(filename, &filecon) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get context of %s", filename)));
	PG_TRY();
	{
		sepgsqlAvcPermission(sepgsqlGetDatabaseContext(),
							 filecon,
							 SECCLASS_DB_DATABASE,
							 DB_DATABASE__LOAD_MODULE,
							 filename);
	}
	PG_CATCH();
	{
		freecon(filecon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(filecon);
}

/*******************************************************************************
 * Binary Large Object hooks
 *******************************************************************************/

void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple)
{
	security_context_t tcontext;
	Oid security_id;

	tcontext = sepgsqlGetDefaultContext(rel, tuple);
	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 tcontext,
						 SECCLASS_DB_BLOB,
						 DB_BLOB__CREATE,
						 sepgsqlTupleName(RelationGetRelid(rel), tuple));
	security_id = pgaceSecurityLabelToSid(tcontext);
	HeapTupleSetSecurity(tuple, security_id);
	pfree(tcontext);
}

void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple,
							bool is_first, Datum *pgaceItem)
{
	List *sidList = is_first ? NIL : (List *)(*pgaceItem);
	ListCell *l;
	security_context_t tcontext;
	Oid security_id = HeapTupleGetSecurity(tuple);

	foreach (l, sidList)
	{
		if (lfirst_oid(l) == security_id)
			return;	/* already checked */
	}
	tcontext = pgaceLookupSecurityLabel(security_id);
	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 tcontext,
						 SECCLASS_DB_BLOB,
						 DB_BLOB__DROP,
						 sepgsqlTupleName(RelationGetRelid(rel), tuple));
	sidList = lappend_oid(sidList, security_id);
	*pgaceItem = PointerGetDatum(sidList);
}

bool sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple,
							bool is_first, Datum *pgaceItem)
{
	struct {
		List *allowList;
		List *denyList;
	} *rd_desc = is_first ? palloc0(sizeof(*rd_desc))
						  : DatumGetPointer(*pgaceItem);
	ListCell *l;
	security_context_t tcontext;
	Oid security_id;
	bool rc;

	security_id = HeapTupleGetSecurity(tuple);
	foreach (l, rd_desc->allowList)
	{
		if (lfirst_oid(l) == security_id)
			return true;	/* already allowed */
	}

	foreach (l, rd_desc->denyList)
	{
		if (lfirst_oid(l) == security_id)
			return false;	/* already denied */
	}

	tcontext = pgaceLookupSecurityLabel(security_id);
	rc = sepgsqlAvcPermissionNoAbort(sepgsqlGetClientContext(),
									 tcontext,
									 SECCLASS_DB_BLOB,
									 DB_BLOB__READ,
									 sepgsqlTupleName(RelationGetRelid(rel), tuple));
	if (rc)
		rd_desc->allowList = lappend_oid(rd_desc->allowList, security_id);
	else
		rd_desc->denyList = lappend_oid(rd_desc->denyList, security_id);

	*pgaceItem = PointerGetDatum(rd_desc);

	return rc;
}

void sepgsqlLargeObjectWrite(Relation rel, Relation idx,
							 HeapTuple newtup, HeapTuple oldtup,
							 bool is_first, Datum *pgaceItem)
{
	security_context_t tcontext;
	Oid security_id;
	ListCell *l;
	struct {
		List *allowList;
		Oid   default_sid;
	} *wr_desc = is_first ? palloc0(sizeof(*wr_desc))
						  : DatumGetPointer(*pgaceItem);

	if (HeapTupleIsValid(newtup))
	{
		if (HeapTupleIsValid(oldtup))
			security_id = HeapTupleGetSecurity(oldtup);
		else if (wr_desc->default_sid != InvalidOid)
			security_id = wr_desc->default_sid;
		else
		{
			SysScanDesc sd;
			ScanKeyData skey;
			HeapTuple tuple;
			Form_pg_largeobject loForm
				= (Form_pg_largeobject) GETSTRUCT(newtup);

			ScanKeyInit(&skey,
						Anum_pg_largeobject_loid,
						BTEqualStrategyNumber, F_OIDEQ,
						ObjectIdGetDatum(loForm->loid));
			sd = systable_beginscan_ordered(rel, idx,
											SnapshotNow, 1, &skey);
			security_id = InvalidOid;
			while ((tuple = systable_getnext_ordered(sd, ForwardScanDirection)) != NULL)
			{
				security_id = HeapTupleGetSecurity(tuple);
				if (security_id != InvalidOid)
					break;
			}
			systable_endscan_ordered(sd);

			if (security_id == InvalidOid)
			{
				tcontext = sepgsqlGetDefaultContext(rel, newtup);
				security_id = pgaceSecurityLabelToSid(tcontext);
			}
			wr_desc->default_sid = security_id;
		}
		HeapTupleSetSecurity(newtup, security_id);
	}
	else
	{
		Assert(HeapTupleIsValid(oldtup));
		security_id = HeapTupleGetSecurity(oldtup);
		newtup = oldtup;
	}

	foreach (l, wr_desc->allowList)
	{
		if (lfirst_oid(l) == security_id)
			return;		/* already allowed */
	}

	tcontext = pgaceLookupSecurityLabel(security_id);
	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 tcontext,
						 SECCLASS_DB_BLOB,
						 DB_BLOB__WRITE,
						 sepgsqlTupleName(RelationGetRelid(rel), newtup));
	wr_desc->allowList = lappend_oid(wr_desc->allowList, security_id);

	*pgaceItem = PointerGetDatum(wr_desc);
}

static void blob_import_export_common(bool import, Oid loid, int fdesc, const char *filename)
{
	Relation rel;
	SysScanDesc sd;
	ScanKeyData skey;
	HeapTuple tuple;
	bool found = false;
	List *sidList = NIL;
	ListCell *l;
	Oid security_id;
	security_context_t tcontext;

	/* db_blob:{import/export} to target object */
	rel = heap_open(LargeObjectRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));
	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);
	while ((tuple = systable_getnext(sd)) != NULL)
	{
		found = true;

		security_id = HeapTupleGetSecurity(tuple);
		foreach (l, sidList)
		{
			if (lfirst_oid(l) == security_id)
				goto next;	/* already allowed */
		}

		tcontext = pgaceLookupSecurityLabel(security_id);
		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 tcontext,
							 SECCLASS_DB_BLOB,
							 import ? DB_BLOB__IMPORT : DB_BLOB__EXPORT,
							 sepgsqlTupleName(RelationGetRelid(rel), tuple));
		sidList = lappend_oid(sidList, security_id);
	next:
		;
	}
	systable_endscan(sd);
	heap_close(rel, AccessShareLock);

	if (!found)
		elog(ERROR, "SELinux: failed to lookup large object: %u", loid);

	/* file:{read} to target file */
	if (!fgetfilecon_raw(fdesc, &tcontext))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get context of %s", filename)));
	PG_TRY();
	{
		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 tcontext,
							 SECCLASS_FILE,
							 import ? FILE__READ : FILE__WRITE,
							 filename);
	}
	PG_CATCH();
	{
		freecon(tcontext);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(tcontext);
}

void sepgsqlLargeObjectImport(Oid loid, int fdesc, const char *filename)
{
	blob_import_export_common(true, loid, fdesc, filename);
}

void sepgsqlLargeObjectExport(Oid loid, int fdesc, const char *filename)
{
	blob_import_export_common(false, loid, fdesc, filename);
}

void sepgsqlLargeObjectGetSecurity(Relation rel, HeapTuple tuple)
{
	Oid security_id = HeapTupleGetSecurity(tuple);
	security_context_t tcontext = pgaceLookupSecurityLabel(security_id);

	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 tcontext,
						 SECCLASS_DB_BLOB,
						 DB_BLOB__GETATTR,
						 sepgsqlTupleName(RelationGetRelid(rel), tuple));
}

void sepgsqlLargeObjectSetSecurity(Relation rel, HeapTuple tuple, Oid security_id,
								   bool is_first, Datum *pgaceItem)
{
	security_context_t tcontext;
	List *sidList = is_first ? NIL : (List *) (*pgaceItem);
	ListCell *l;

	foreach (l, sidList)
	{
		if (lfirst_oid(l) == security_id)
			return;		/* already checked */
	}

	/* check db_blob:{setattr relabelfrom} */
	tcontext = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));
	sepgsqlAvcPermission(sepgsqlGetClientContext(),
						 tcontext,
						 SECCLASS_DB_BLOB,
						 DB_BLOB__SETATTR | DB_BLOB__RELABELFROM,
						 sepgsqlTupleName(RelationGetRelid(rel), tuple));
	sidList = lappend_oid(sidList, HeapTupleGetSecurity(tuple));

	/* check db_blob:{setattr relabelto} */
	if (is_first)
	{
		tcontext = pgaceLookupSecurityLabel(security_id);
		sepgsqlAvcPermission(sepgsqlGetClientContext(),
							 tcontext,
							 SECCLASS_DB_BLOB,
							 DB_BLOB__RELABELTO,
							 sepgsqlTupleName(RelationGetRelid(rel), tuple));
	}
	*pgaceItem = PointerGetDatum(sidList);
}

/*******************************************************************************
 * ExecScan hooks
 *******************************************************************************/
static bool abort_on_violated_tuple = false;

bool sepgsqlExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	HeapTuple tuple;
	uint32 perms = scan->pgaceTuplePerms;

	if (!perms)
		return true;

	tuple = ExecMaterializeSlot(slot);

	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms,
								  abort_on_violated_tuple);
}

/* ----------------------------------------------------------
 * special cases in foreign key constraint
 * ---------------------------------------------------------- */
Datum sepgsqlPreparePlanCheck(Relation rel) {
	Datum pgace_saved = BoolGetDatum(abort_on_violated_tuple);

	abort_on_violated_tuple = true;

	return pgace_saved;
}

void sepgsqlRestorePlanCheck(Relation rel, Datum pgace_saved) {
	abort_on_violated_tuple = DatumGetBool(pgace_saved);
}

/*******************************************************************************
 * security_label hooks
 *******************************************************************************/
char *sepgsqlTranslateSecurityLabelIn(char *context)
{
	security_context_t i_context;
	char *result;

	if (selinux_trans_to_raw_context((security_context_t) context, &i_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
	PG_TRY();
	{
		result = pstrdup(i_context);
	}
	PG_CATCH();
	{
		freecon(i_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(i_context);

	return result;
}

char *sepgsqlTranslateSecurityLabelOut(char *context)
{
	security_context_t o_context;
	char *result;

	if (selinux_raw_to_trans_context((security_context_t) context, &o_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate mls label")));
	PG_TRY();
	{
		result = pstrdup(o_context);
	}
	PG_CATCH();
	{
		freecon(o_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(o_context);

	return result;
}

/*
 * sepgsqlValidateSecurityLabel() checks whether the given context
 * is valid for the current policy, or not.
 * If not valid, it returns alternative context.
 */
char *sepgsqlValidateSecurityLabel(char *context)
{
	security_context_t unlabeled;
	char *result;

	if (context != NULL)
	{
		if (security_check_context_raw((security_context_t) context) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: %s is invalid security context", context)));
		return context;
	}

	if (security_get_initial_context_raw("unlabeled", &unlabeled))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get unlabeled context")));
	PG_TRY();
	{
		result = pstrdup(unlabeled);
	}
	PG_CATCH();
	{
		freecon(unlabeled);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(unlabeled);

	return result;
}

char *sepgsqlSecurityLabelOfLabel(void)
{
	security_context_t table_context, tuple_context;
	HeapTuple tuple;

	/* obtain security context of pg_security */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SecurityRelationId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", SecurityRelationId);

	table_context = pgaceLookupSecurityLabel(HeapTupleGetSecurity(tuple));

	tuple_context = sepgsqlAvcCreateCon(sepgsqlGetServerContext(),
										table_context,
										SECCLASS_DB_TUPLE);
	pfree(table_context);

	ReleaseSysCache(tuple);

	return tuple_context;
}

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/
static HeapTuple getHeapTupleFromItemPointer(Relation rel, ItemPointer tid)
{
	/* obtain an old tuple */
	Buffer		buffer;
	PageHeader	dp;
	ItemId		lp;
	HeapTupleData tuple;
	HeapTuple oldtup;

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

static bool trustedRelationForInternal(Relation rel)
{
	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return true;

	switch (RelationGetRelid(rel))
	{
	case LargeObjectRelationId:
	case SecurityRelationId:
		return true;
		break;
	}
	return false;
}

bool sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
							bool is_internal, bool with_returning)
{
	security_context_t context;
	Oid security_id;
	uint32 perms;

	/* default context for no explicit labeled tuple */
	if (HeapTupleGetSecurity(tuple) == InvalidOid)
	{
		context = sepgsqlGetDefaultContext(rel, tuple);
		security_id = pgaceSecurityLabelToSid(context);
		HeapTupleSetSecurity(tuple, security_id);
	}

	if (is_internal && trustedRelationForInternal(rel))
		return true;

	perms = SEPGSQL_PERMS_INSERT;
	if (with_returning)
		perms |= SEPGSQL_PERMS_SELECT;

	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms, is_internal);
}

bool  sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
							 bool is_internal, bool with_returning)
{
	HeapTuple oldtup;
	uint32 perms;
	bool rc = true;

	oldtup = getHeapTupleFromItemPointer(rel, otid);

	if (HeapTupleGetSecurity(newtup) == InvalidOid)
	{
		Oid security_id = HeapTupleGetSecurity(oldtup);

		HeapTupleSetSecurity(newtup, security_id);
	}

	if (is_internal && trustedRelationForInternal(rel))
		goto out;

	if (is_internal)
	{
		perms = SEPGSQL_PERMS_UPDATE;
		if (HeapTupleGetSecurity(newtup) != HeapTupleGetSecurity(oldtup))
			perms |= SEPGSQL_PERMS_RELABELFROM;
		else if (with_returning)
			perms |= SEPGSQL_PERMS_SELECT;
		rc = sepgsqlCheckTuplePerms(rel, oldtup, NULL, perms, is_internal);
		if (!rc)
			goto out;
	}

	if (HeapTupleGetSecurity(newtup) != HeapTupleGetSecurity(oldtup)) {
		perms = SEPGSQL_PERMS_RELABELTO;
		if (with_returning)
			perms |= SEPGSQL_PERMS_SELECT;
		rc = sepgsqlCheckTuplePerms(rel, newtup, oldtup, perms, is_internal);
	}
out:
	heap_freetuple(oldtup);
	return rc;
}

bool  sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid,
							 bool is_internal, bool with_returning)
{
	HeapTuple oldtup;
	uint32 perms = SEPGSQL_PERMS_DELETE;
	bool rc = true;

	if (is_internal)
	{
		if (trustedRelationForInternal(rel))
			return true;

		oldtup = getHeapTupleFromItemPointer(rel, otid);
		if (with_returning)
			perms |= SEPGSQL_PERMS_SELECT;
		rc = sepgsqlCheckTuplePerms(rel, oldtup, NULL, perms, is_internal);
		heap_freetuple(oldtup);
	}
	return rc;
}
