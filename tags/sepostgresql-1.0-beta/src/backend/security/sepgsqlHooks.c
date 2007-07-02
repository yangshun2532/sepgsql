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

	dp = (PageHeader) BufferGetPage(buffer);
	lp = PageGetItemId(dp, ItemPointerGetOffsetNumber(tid));

	Assert(ItemIdIsUsed(lp));

	tuple.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_self = *tid;
	tuple.t_tableOid = RelationGetRelid(rel);

	oldtup = heap_copytuple(&tuple);
	ReleaseBuffer(buffer);

	return oldtup;
}

/*******************************************************************************
 * Extended SQL statement hooks
 *******************************************************************************/
/* make context = 'xxx' node */
DefElem *sepgsqlGramSecurityLabel(char *defname, char *context) {
	DefElem *n = NULL;
	if (!strcmp(defname, "context"))
		n = makeDefElem(pstrdup(defname), (Node *) makeString(context));
	return n;
}

/* whether DefElem holds security context, or not */
bool sepgsqlNodeIsSecurityLabel(DefElem *defel) {
	Assert(IsA(defel, DefElem));
	if (defel->defname && !strcmp(defel->defname, "context"))
		return true;
	return false;
}

/* parse explicitly specified security context */
Oid sepgsqlParseSecurityLabel(DefElem *defel) {
	Datum newcon;
	Assert(IsA(defel, DefElem));

	newcon = DirectFunctionCall1(security_label_in,
								 CStringGetDatum(strVal(defel->arg)));
	return DatumGetObjectId(newcon);
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
						   SECCLASS_DATABASE,
						   DATABASE__GET_PARAM,
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
						   SECCLASS_DATABASE,
						   DATABASE__SET_PARAM,
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
							   SECCLASS_TABLE,
							   TABLE__LOCK,
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
	uint32 perms = PROCEDURE__EXECUTE;

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

		perms |= PROCEDURE__ENTRYPOINT;
	}

	if (with_perm_check) {
		/* check procedure:{execute entrypoint} permission */
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_PROCEDURE,
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
	if (oldtup && !sepgsqlCheckTuplePerms(rel, oldtup, NULL, TUPLE__SELECT, false))
		return false;
	if (newtup && !sepgsqlCheckTuplePerms(rel, newtup, NULL, TUPLE__SELECT, false))
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
						   SECCLASS_DATABASE,
						   DATABASE__LOAD_MODULE,
						   (char *) filename);
}

/*******************************************************************************
 * Binary Large Object hooks
 *******************************************************************************/
Oid sepgsqlLargeObjectGetSecurity(HeapTuple tuple) {
	Oid lo_security = HeapTupleGetSecurity(tuple);

	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   lo_security,
						   SECCLASS_BLOB,
						   BLOB__GETATTR,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
	return lo_security;
}

void sepgsqlLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first)
{
	if (is_first) {
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_BLOB,
							   BLOB__SETATTR | BLOB__RELABELFROM,
							   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   lo_security,
							   SECCLASS_BLOB,
							   BLOB__RELABELTO,
							   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
	}
	HeapTupleSetSecurity(tuple, lo_security);
}

void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple)
{
	Oid newcon = sepgsqlComputeImplicitContext(rel, tuple);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   newcon,
						   SECCLASS_BLOB,
						   BLOB__CREATE,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
	HeapTupleSetSecurity(tuple, newcon);
}

void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_BLOB,
						   BLOB__DROP,
						   sepgsqlGetTupleName(LargeObjectRelationId, tuple));
}

void sepgsqlLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only)
{
	sepgsqlCheckTuplePerms(rel, tuple, NULL, TUPLE__SELECT, true);
}

void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple)
{
	sepgsqlCheckTuplePerms(rel, tuple, NULL, TUPLE__SELECT | BLOB__READ, true);
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
	sepgsqlCheckTuplePerms(rel, newtup, NULL, TUPLE__UPDATE | BLOB__WRITE, true);
}

void sepgsqlLargeObjectImport()
{
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   sepgsqlGetServerContext(),
						   SECCLASS_BLOB,
						   BLOB__IMPORT,
						   NULL);
}

void sepgsqlLargeObjectExport()
{
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   sepgsqlGetServerContext(),
						   SECCLASS_BLOB,
						   BLOB__EXPORT,
						   NULL);
}

/*******************************************************************************
 * security_label hooks
 *******************************************************************************/
char *sepgsqlSecurityLabelIn(char *context) {
	security_context_t raw_context;
	char *result;

	if (selinux_trans_to_raw_context(context, &raw_context))
        selerror("could not translate MLS label");
	PG_TRY();
	{
		result = pstrdup(raw_context);
	}
	PG_CATCH();
	{
		freecon(raw_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(raw_context);

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

bool sepgsqlSecurityLabelIsValid(char *context) {
	if (!security_check_context_raw(context))
		return true;
	return false;
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
	rc = security_compute_create_raw(scon, tcon, SECCLASS_TUPLE, &ncon);
	pfree(tcon);
	freecon(scon);
	if (rc)
		selerror("could not compute a newly created security context");

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

extern char *selinux_mnt;

char *sepgsqlSecurityLabelNotFound(Oid sid) {
	security_context_t unlabeled_con;

#ifndef SEPGSQLOPT_LIBSELINUX_1_33
	if (!security_get_initial_context_raw("unlabeled", &unlabeled_con)) {
		char *result;

		PG_TRY();
		{
			result = pstrdup(unlabeled_con);
		}
		PG_CATCH();
		{
			freecon(unlabeled_con);
			PG_RE_THROW();
		}
		PG_END_TRY();
		freecon(unlabeled_con);
		return result;
	}
#endif
	/* FIXME: This fallback code should be eliminated in the near future.
	 * /selinux/init_contexts support will be enabled at 2.6.22 kernel.
	 */
	unlabeled_con = "system_u:object_r:unlabeled_t:s0";
	if (sepgsqlSecurityLabelIsValid(unlabeled_con))
		return pstrdup(unlabeled_con);
	unlabeled_con = "system_u:object_r:unlabeled_t";
	if (sepgsqlSecurityLabelIsValid(unlabeled_con))
		return pstrdup(unlabeled_con);
	return NULL;
}

/*******************************************************************************
 * simple_heap_xxxx hooks
 *******************************************************************************/
static inline bool __is_simple_system_relation(Relation rel)
{
	bool retval = false;
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
		retval = true;
		break;
	}
	return retval;
}

void sepgsqlSimpleHeapInsert(Relation rel, HeapTuple tuple)
{
	Oid newcon;

	if (!__is_simple_system_relation(rel))
		return;

	newcon = HeapTupleGetSecurity(tuple);
	if (newcon == InvalidOid) {
		/* no explicit labeling */
		newcon = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, newcon);
	}
	sepgsqlCheckTuplePerms(rel, tuple, NULL, TUPLE__INSERT, true);
}

void sepgsqlSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple newtup)
{
	HeapTuple oldtup;
	Oid ncon, ocon;
	uint32 perms = TUPLE__UPDATE;

	if (!__is_simple_system_relation(rel))
		return;

	oldtup = __getHeapTupleFromItemPointer(rel, tid);
	ncon = HeapTupleGetSecurity(newtup);
	ocon = HeapTupleGetSecurity(oldtup);
	if (ncon == InvalidOid) {
		HeapTupleSetSecurity(newtup, ocon);
		ncon = ocon;
	}
	if (ncon != ocon)
		perms |= TUPLE__RELABELFROM;
	sepgsqlCheckTuplePerms(rel, oldtup, NULL, perms, true);

	perms = (ncon != ocon ? TUPLE__RELABELTO : 0);
	sepgsqlCheckTuplePerms(rel, newtup, oldtup, perms, true);

	heap_freetuple(oldtup);
}

void sepgsqlSimpleHeapDelete(Relation rel, ItemPointer tid)
{
	HeapTuple oldtup;

	if (!__is_simple_system_relation(rel))
		return;

	oldtup = __getHeapTupleFromItemPointer(rel, tid);
	sepgsqlCheckTuplePerms(rel, oldtup, NULL, TUPLE__DELETE, true);
	heap_freetuple(oldtup);
}

/*******************************************************************************
 * ExecInsert/Delete/Update hooks
 *******************************************************************************/

bool sepgsqlExecInsert(Relation rel, HeapTuple tuple, bool with_returning)
{
	Oid newcon;
	uint32 perms;

	if (!sepgsqlIsEnabled())
		return true;	/* always true, if disabled */

	newcon = HeapTupleGetSecurity(tuple);
	if (newcon == InvalidOid) {
		/* no explicit labeling */
		newcon = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, newcon);
	}
	perms = TUPLE__INSERT;
	if (with_returning)
		perms |= TUPLE__SELECT;

	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms, false);
}

bool sepgsqlExecUpdate(Relation rel, HeapTuple newtup, ItemPointer tid, bool with_returning)
{
	HeapTuple oldtup;
	Oid newcon, oldcon;
	uint32 perms = 0;
	bool rc;

	oldtup = __getHeapTupleFromItemPointer(rel, tid);
	newcon = HeapTupleGetSecurity(newtup);
	oldcon = HeapTupleGetSecurity(oldtup);
	if (newcon == InvalidOid) {
		HeapTupleSetSecurity(newtup, oldcon);		/* keep old context */
		oldcon = newcon;
	}
	if (newcon != oldcon) {
		perms |= TUPLE__RELABELTO;
		if (with_returning)
			perms |= TUPLE__SELECT;
	}
	rc = sepgsqlCheckTuplePerms(rel, newtup, oldtup, perms, false);

	heap_freetuple(oldtup);

	return rc;
}

bool sepgsqlExecDelete(Relation rel, ItemPointer tid, bool with_returning)
{
	HeapTuple oldtup;
	bool rc;

	oldtup = __getHeapTupleFromItemPointer(rel, tid);

	rc = sepgsqlCheckTuplePerms(rel, oldtup, NULL, 0, false);

	heap_freetuple(oldtup);

	return rc;
}

/*******************************************************************************
 * heap_insert/heap_update hooks -- the last gate of implicit labeling
 *******************************************************************************/
void sepgsqlHeapInsert(Relation rel, HeapTuple tuple)
{
	if (HeapTupleGetSecurity(tuple) == InvalidOid) {
		Oid newcon = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, newcon);
	}
}

void sepgsqlHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	if (HeapTupleGetSecurity(newtup) == InvalidOid) {
		Oid oldcon = HeapTupleGetSecurity(oldtup);
		HeapTupleSetSecurity(newtup, oldcon);
	}
}
