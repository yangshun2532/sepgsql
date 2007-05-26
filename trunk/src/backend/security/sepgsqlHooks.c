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
	Form_pg_database db_form;
	HeapTuple tuple;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for database %u", MyDatabaseId);
	db_form = (Form_pg_database) GETSTRUCT(tuple);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__GET_PARAM,
						   NameStr(db_form->datname));
	ReleaseSysCache(tuple);
}

void sepgsqlSetDatabaseParam(const char *name, char *argstring)
{
	Form_pg_database db_form;
	HeapTuple tuple;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for database %u", MyDatabaseId);
	db_form = (Form_pg_database) GETSTRUCT(tuple);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__SET_PARAM,
						   NameStr(db_form->datname));
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * RELATION(Table)/ATTRIBTUE(column) object related hooks
 *******************************************************************************/
void sepgsqlLockTable(Oid relid)
{
	HeapTuple tuple;
	Form_pg_class pgclass;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", relid);
	pgclass = (Form_pg_class) GETSTRUCT(tuple);

    sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_TABLE,
						   TABLE__LOCK,
						   NameStr(pgclass->relname));
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
		Form_pg_proc proc_form = (Form_pg_proc) GETSTRUCT(tuple);

		/* check procedure:{execute entrypoint} permission */
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_PROCEDURE,
							   perms,
							   NameStr(proc_form->proname));
	}
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * COPY TO/COPY FROM related hooks
 *******************************************************************************/

void sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom)
{
	HeapTuple tuple;
	Form_pg_class pgclass;
	uint32 perms;
	ListCell *l;

	/* on 'COPY FROM SELECT ...' cases, any checkings are done in select.c */
	if (rel == NULL)
		return;

	/* 1. check table:select/insert permission */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(RelationGetRelid(rel)),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));
	pgclass = (Form_pg_class) GETSTRUCT(tuple);

	perms = (isFrom ? TABLE__INSERT : TABLE__SELECT);
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_TABLE,
						   perms,
						   NameStr(pgclass->relname));
	ReleaseSysCache(tuple);

	/* 2. check column:select/insert for each column */
	perms = (isFrom ? COLUMN__INSERT : COLUMN__SELECT);
	foreach (l, attNumList) {
		Form_pg_attribute pgattr;
		AttrNumber attno = lfirst_int(l);

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("cache lookup failed for attribute %d, relation %u",
					 attno, RelationGetRelid(rel));
		pgattr = (Form_pg_attribute) GETSTRUCT(tuple);

		perms = (isFrom ? COLUMN__INSERT : COLUMN__SELECT);
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_COLUMN,
							   perms,
							   NameStr(pgattr->attname));
		ReleaseSysCache(tuple);
	}
}

bool sepgsqlCopyToTuple(Relation rel, HeapTuple tuple)
{
	return sepgsqlCheckTuplePerms(rel, tuple, NULL, TUPLE__SELECT, false);
}

bool sepgsqlCopyFromTuple(Relation rel, HeapTuple tuple)
{
	Oid tcontext = HeapTupleGetSecurity(tuple);

	if (tcontext == InvalidOid) {
		/* implicit labeling */
		tcontext = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, tcontext);
	}
	return sepgsqlCheckTuplePerms(rel, tuple, NULL, TUPLE__INSERT, false);
}

/*******************************************************************************
 * LOAD shared library module hook
 *******************************************************************************/
void sepgsqlLoadSharedModule(const char *filename)
{
	security_context_t filecon;
	Datum filecon_sid;

	if (getfilecon(filename, &filecon) < 1)
		selerror("could not obtain security context of %s", filename);
	PG_TRY();
	{
		filecon_sid = DirectFunctionCall1(security_label_in,
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
						   NULL);
	return lo_security;
}

void sepgsqlLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first)
{
	if (is_first) {
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_BLOB,
							   BLOB__SETATTR | BLOB__RELABELFROM,
							   NULL);
		sepgsql_avc_permission(sepgsqlGetClientContext(),
							   lo_security,
							   SECCLASS_BLOB,
							   BLOB__RELABELTO,
							   NULL);
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
						   NULL);
	HeapTupleSetSecurity(tuple, newcon);
}

void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientContext(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_BLOB,
						   BLOB__DROP,
						   NULL);
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

	/* obtain a security context of pg_database */
	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for database = %u", MyDatabaseId);
	tcon = DatumGetCString(DirectFunctionCall1(security_label_raw_out,
											   ObjectIdGetDatum(HeapTupleGetSecurity(tuple))));
	ReleaseSysCache(tuple);

	/* obtain server's context */
	rc = getcon_raw(&scon);
	if (rc)
		selerror("could not obtain server's context");

	/* compute pg_selinux tuple context */
	rc = security_compute_create_raw(scon, tcon, SECCLASS_DATABASE, &ncon);
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
    static char *unlabeled_mls = "system_u:object_r:unlabeled_t:s0";
	static char *unlabeled = "system_u:object_r:unlabeled_t";
	char buffer[PATH_MAX];
	int rc, fd;

	if (selinux_mnt) {
		snprintf(buffer, sizeof(buffer),
				 "%s/initial_contexts/unlabeled",
				 selinux_mnt);
		fd = open(buffer, O_RDONLY);
		if (fd < 0)
			goto no_interface;

		rc = read(fd, buffer, sizeof(buffer) - 1);
		close(fd);

		if (rc < 0)
			goto no_interface;

		return pstrdup(buffer);
	}
	/* NOTE: This fallback routine should be eliminated in the near future. *
	 * Due to its ad-hoc assumption. */
no_interface:
	if (sepgsqlSecurityLabelIsValid(unlabeled_mls))
		return pstrdup(unlabeled_mls);
	if (sepgsqlSecurityLabelIsValid(unlabeled))
		return pstrdup(unlabeled);
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

	if (!sepgsqlIsEnabled())
		return;

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

	if (RelationGetRelid(rel) == SecurityRelationId)
		selerror("INSERT INTO pg_selinux ..., never allowed");

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

	if (RelationGetRelid(rel) == SecurityRelationId)
		selerror("UPDATE pg_selinux ..., never allowed");

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

	if (RelationGetRelid(rel) == SecurityRelationId)
		selerror("DELETE FROM pg_selinux ..., never allowed");

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
