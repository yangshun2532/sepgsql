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
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/pgace.h"
#include "security/sepgsql.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static HeapTuple __getHeapTupleFromItemPointer(Relation rel, ItemPointer tid)
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

	Assert(ItemIdIsUsed(lp));

	tuple.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_self = *tid;
	tuple.t_tableOid = RelationGetRelid(rel);
	oldtup = heap_copytuple(&tuple);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	ReleaseBuffer(buffer);

	return oldtup;
}

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

static void __put_gram_context(HeapTuple tuple, DefElem *defel)
{
	if (defel) {
		Oid newcon = DirectFunctionCall1(security_label_in,
										 CStringGetDatum(strVal(defel->arg)));
		HeapTupleSetSecurity(tuple, newcon);
	}
}

void sepgsqlGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

void sepgsqlGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

void sepgsqlGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

void sepgsqlGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

void sepgsqlGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

void sepgsqlGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

void sepgsqlGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

void sepgsqlGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	__put_gram_context(tuple, defel);
}

/*******************************************************************************
 * DATABASE object related hooks
 *******************************************************************************/

void sepgsqlGetDatabaseParam(const char *name)
{
	HeapTuple tuple;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for database %u", MyDatabaseId);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_DATABASE,
						   DB_DATABASE__GET_PARAM,
						   sepgsqlGetTupleName(DatabaseRelationId, tuple));
	ReleaseSysCache(tuple);
}

void sepgsqlSetDatabaseParam(const char *name, char *argstring)
{
	HeapTuple tuple;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for database %u", MyDatabaseId);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_DATABASE,
						   DB_DATABASE__SET_PARAM,
						   sepgsqlGetTupleName(DatabaseRelationId, tuple));
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * RELATION(Table)/ATTRIBTUE(column) object related hooks
 *******************************************************************************/
void sepgsqlLockTable(Oid relid)
{
	HeapTuple tuple;
	Form_pg_class classForm;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", relid);
	classForm = (Form_pg_class) GETSTRUCT(tuple);

	if (classForm->relkind == RELKIND_RELATION)
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_DB_TABLE,
							   DB_TABLE__LOCK,
							   sepgsqlGetTupleName(RelationRelationId, tuple));
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * PROCEDURE related hooks
 *******************************************************************************/

static Datum __callTrustedProcedure(PG_FUNCTION_ARGS)
{
	Oid orig_client_con;
	Datum retval;

	/* save original security context */
	orig_client_con = sepgsqlGetClientContext();
	/* set exec context */
	sepgsqlSetClientContext(DatumGetObjectId(fcinfo->flinfo->fn_pgace_data));
	PG_TRY();
	{
		retval = fcinfo->flinfo->fn_pgace_addr(fcinfo);
	}
	PG_CATCH();
	{
		sepgsqlSetClientContext(orig_client_con);
		PG_RE_THROW();
	}
	PG_END_TRY();
	sepgsqlSetClientContext(orig_client_con);

	return retval;
}

void sepgsqlCallFunction(FmgrInfo *finfo, bool with_perm_check)
{
	HeapTuple tuple;
	Oid execcon;
	uint32 perms = DB_PROCEDURE__EXECUTE;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(finfo->fn_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for procedure %u", finfo->fn_oid);

	/* check trusted procedure */
	execcon = sepgsql_avc_createcon(sepgsqlGetClientContext(),
									HeapTupleGetSecurity(tuple),
									SECCLASS_PROCESS);
	if (sepgsqlGetClientContext() != execcon) {
		finfo->fn_pgace_addr = finfo->fn_addr;
		finfo->fn_pgace_data = ObjectIdGetDatum(execcon);
		finfo->fn_addr = __callTrustedProcedure;

		perms |= DB_PROCEDURE__ENTRYPOINT;
	}

	if (with_perm_check) {
		/* check procedure:{execute entrypoint} permission */
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_DB_PROCEDURE,
							   perms,
							   sepgsqlGetTupleName(ProcedureRelationId, tuple));
	}
	ReleaseSysCache(tuple);
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
		selerror("unknown trigger event type (%u)", tgdata->tg_event);
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
	Datum filecon_sid;

	if (getfilecon_raw(filename, &filecon) < 1)
		selerror("could not obtain security context of %s", filename);
	PG_TRY();
	{
		filecon_sid = DirectFunctionCall1(security_label_raw_in,
										  CStringGetDatum(filecon));
	}
	PG_CATCH();
	{
		freecon(filecon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(filecon);

	sepgsql_avc_permission(sepgsqlGetDatabaseContext(),
						   DatumGetObjectId(filecon_sid),
						   SECCLASS_DB_DATABASE,
						   DB_DATABASE__LOAD_MODULE,
						   (char *) filename);
}

/*******************************************************************************
 * Binary Large Object hooks
 *******************************************************************************/
void sepgsqlLargeObjectGetSecurity(HeapTuple tuple) {
	Oid lo_security = HeapTupleGetSecurity(tuple);

	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   lo_security,
						   SECCLASS_DB_BLOB,
						   DB_BLOB__GETATTR,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
}

void sepgsqlLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security)
{
	/* check db_blob:{setattr relabelfrom} */
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_BLOB,
						   DB_BLOB__SETATTR | DB_BLOB__RELABELFROM,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));

	/* check db_blob:{relabelto} */
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   lo_security,
						   SECCLASS_DB_BLOB,
						   DB_BLOB__RELABELTO,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
}

void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple)
{
	Oid newcon = sepgsqlComputeImplicitContext(rel, tuple);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   newcon,
						   SECCLASS_DB_BLOB,
						   DB_BLOB__CREATE,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
	HeapTupleSetSecurity(tuple, newcon);
}

void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DB_BLOB,
						   DB_BLOB__DROP,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
}

void sepgsqlLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only)
{
	sepgsqlCheckTuplePerms(rel, tuple, NULL, SEPGSQL_PERMS_SELECT, true);
}

void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple)
{
	sepgsqlCheckTuplePerms(rel, tuple, NULL, SEPGSQL_PERMS_SELECT | SEPGSQL_PERMS_READ, true);
}

void sepgsqlLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	Oid lo_security;

	if (HeapTupleIsValid(oldtup)) {
		lo_security = HeapTupleGetSecurity(oldtup);
	} else {
		Form_pg_largeobject lobj_form
			= (Form_pg_largeobject) GETSTRUCT(newtup);
		ScanKeyData skey;
		SysScanDesc sd;
		HeapTuple tuple;

		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(lobj_form->loid));
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotNow, 1, &skey);
		tuple = systable_getnext(sd);
		if (!HeapTupleIsValid(tuple))
			selerror("large object %u does not exist", lobj_form->loid);
		lo_security = HeapTupleGetSecurity(tuple);
		systable_endscan(sd);
	}
	HeapTupleSetSecurity(newtup, lo_security);
	sepgsqlCheckTuplePerms(rel, newtup, NULL, SEPGSQL_PERMS_UPDATE | SEPGSQL_PERMS_WRITE, true);
}

void sepgsqlLargeObjectTruncate(Relation rel, Oid loid) {
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple;

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));
	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);
	tuple = systable_getnext(sd);
	if (!HeapTupleIsValid(tuple))
		selerror("large object %u does not exist", loid);
	sepgsqlCheckTuplePerms(rel, tuple, NULL, SEPGSQL_PERMS_UPDATE | SEPGSQL_PERMS_WRITE, true);
	systable_endscan(sd);
}

void sepgsqlLargeObjectImport()
{
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   sepgsqlGetServerContext(),
						   SECCLASS_DB_BLOB,
						   DB_BLOB__IMPORT,
						   NULL);
}

void sepgsqlLargeObjectExport()
{
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   sepgsqlGetServerContext(),
						   SECCLASS_DB_BLOB,
						   DB_BLOB__EXPORT,
						   NULL);
}

/*******************************************************************************
 * security_label hooks
 *******************************************************************************/
char *sepgsqlSecurityLabelIn(char *context) {
	security_context_t raw_context, canonical_context;
	char *result;
	int rc;

	rc = selinux_trans_to_raw_context(context, &raw_context);
	if (rc)
		selerror("could not translate MLS label");

	rc = security_canonicalize_context_raw(raw_context, &canonical_context);
	freecon(raw_context);
	if (rc)
		selerror("could not canonicalize the context");

	PG_TRY();
	{
		result = pstrdup(canonical_context);
	}
	PG_CATCH();
	{
		freecon(canonical_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(canonical_context);

	return result;
}

char *sepgsqlSecurityLabelOut(char *raw_context) {
	security_context_t context;
	char *result;

	if (selinux_raw_to_trans_context(raw_context, &context))
		selerror("could not translate MLS label");
	PG_TRY();
	{
		result = pstrdup(context);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);

	return result;
}

char *sepgsqlSecurityLabelCheckValid(char *context) {
	security_context_t unlbl_con;
	char *unlbl_result = NULL;

	if (context && !security_check_context_raw(context))
		return context;

	/* context is invalid one */
	if (security_get_initial_context_raw("unlabeled", &unlbl_con))
		elog(ERROR, "SELinux: could not assign an alternative security context");
	PG_TRY();
	{
		unlbl_result = pstrdup(unlbl_con);
	}
	PG_CATCH();
	{
		freecon(unlbl_con);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(unlbl_con);

	return unlbl_result;
}

char *sepgsqlSecurityLabelOfLabel(char *context) {
	HeapTuple tuple;
	security_context_t scon, tcon, ncon, _ncon;
	int rc;

	/* obtain the security context of pg_security */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SecurityRelationId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("pg_security (relid=%u) not found", SecurityRelationId);
	tcon = DatumGetCString(DirectFunctionCall1(security_label_raw_out,
											   ObjectIdGetDatum(HeapTupleGetSecurity(tuple))));
	ReleaseSysCache(tuple);

	/* obtain server's context */
	rc = getcon_raw(&scon);
	if (rc)
		selerror("could not obtain server's context");

	/* compute pg_selinux tuple context */
	rc = security_compute_create_raw(scon, tcon, SECCLASS_DB_TUPLE, &ncon);
	pfree(tcon);
	freecon(scon);
	if (rc)
		elog(ERROR, "SELinux: could not compute label of pg_security");

	/* copy tuple's context */
	PG_TRY();
	{
		_ncon = pstrdup(ncon);
	}
	PG_CATCH();
	{
		freecon(ncon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(ncon);

	return _ncon;
}

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/
static bool __HeapTupleInternalCheckRelation(Relation rel)
{
	switch (RelationGetRelid(rel)) {
	case AggregateRelationId:
	case AttributeRelationId:
	case AuthIdRelationId:
	case CastRelationId:
	case ConversionRelationId:
	case DatabaseRelationId:
	case LanguageRelationId:
	case NamespaceRelationId:
	case OperatorRelationId:
	case OperatorClassRelationId:
	case ProcedureRelationId:
	case RelationRelationId:
	case RewriteRelationId:
	case TableSpaceRelationId:
	case TriggerRelationId:
	case TypeRelationId:
		return true;
		break;
	}
	return false;
}

bool  sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
							 bool is_internal, bool with_returning)
{
	uint32 perms;

	/* default context for no explicit labeled tuple */
	if (HeapTupleGetSecurity(tuple) == InvalidOid) {
		Oid newcon = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, newcon);
	}
	if (is_internal && !__HeapTupleInternalCheckRelation(rel))
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

	oldtup = __getHeapTupleFromItemPointer(rel, otid);

	if (HeapTupleGetSecurity(newtup) == InvalidOid) {
		/* keep old context for no explicit labeled tuple */
		HeapTupleSetSecurity(newtup, HeapTupleGetSecurity(oldtup));
	}

	if (is_internal && !__HeapTupleInternalCheckRelation(rel))
		goto out;

	if (is_internal) {
		perms = SEPGSQL_PERMS_UPDATE;
		if (HeapTupleGetSecurity(newtup) != HeapTupleGetSecurity(oldtup))
			perms |= SEPGSQL_PERMS_RELABELFROM;
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
	uint32 perms;
	bool rc = true;

	if (is_internal) {
		if (!__HeapTupleInternalCheckRelation(rel))
			return true;

		oldtup = __getHeapTupleFromItemPointer(rel, otid);
		perms = SEPGSQL_PERMS_DELETE;
		if (with_returning)
			perms |= SEPGSQL_PERMS_SELECT;
		rc = sepgsqlCheckTuplePerms(rel, oldtup, NULL, perms, is_internal);
		heap_freetuple(oldtup);
	}
	return rc;
}
