/*
 * src/backend/sepgsqlHooks.c
 *   SE-PostgreSQL hooks
 *
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/skey.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_selinux.h"
#include "catalog/pg_trigger.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "security/sepgsql_internal.h"
#include "utils/fmgroids.h"

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
 * DATABASE object related hooks
 *******************************************************************************/

void sepgsqlAlterDatabaseContext(Relation rel, HeapTuple tuple, char *new_context)
{
	Datum ncon;

	Assert(RelationGetRelid(rel) == DatabaseRelationId);
	if (new_context) {
		if (!sepgsqlIsEnabled())
			selerror("SE-PostgreSQL is disabled");

		ncon = DirectFunctionCall1(psid_in, CStringGetDatum(new_context));
		HeapTupleSetSecurity(tuple, DatumGetObjectId(ncon));
	}
}

void sepgsqlGetParamDatabase()
{
	HeapTuple tuple;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for database %u", MyDatabaseId);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__GET_PARAM,
						   HeapTupleGetDatabaseName(tuple));
	ReleaseSysCache(tuple);
}

void sepgsqlSetParamDatabase()
{
	HeapTuple tuple;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for database %u", MyDatabaseId);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__SET_PARAM,
						   HeapTupleGetDatabaseName(tuple));
	ReleaseSysCache(tuple);
}

/*******************************************************************************
 * RELATION(Table)/ATTRIBTUE(column) object related hooks
 *******************************************************************************/

void sepgsqlAlterTableSetTableContext(Relation rel, Value *context)
{
	Relation pgclass;
	HeapTuple tuple;
	psid newcon, oldcon;
	Datum datum;

	if (!sepgsqlIsEnabled())
		selerror("SE-PostgreSQL is disabled");

	pgclass = heap_open(RelationRelationId, RowExclusiveLock);

	/* lookup old security context */
	tuple = SearchSysCacheCopy(RELOID,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));
	oldcon = HeapTupleGetSecurity(tuple);

	/* lookup new security context */
	datum = DirectFunctionCall1(psid_in, CStringGetDatum(strVal(context)));
	newcon = DatumGetObjectId(datum);

	/* 1. check table:{setattr relabelfrom} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   oldcon,
						   SECCLASS_TABLE,
						   TABLE__SETATTR | TABLE__RELABELFROM,
						   HeapTupleGetRelationName(tuple));

	/* 2. check table:{relabelto} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   newcon,
						   SECCLASS_TABLE,
						   TABLE__RELABELTO,
						   HeapTupleGetRelationName(tuple));

	/* 3. update pg_class */
	HeapTupleSetSecurity(tuple, newcon);
	simple_heap_update(pgclass, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pgclass, tuple);

	heap_freetuple(tuple);
	heap_close(pgclass, RowExclusiveLock);
}

void sepgsqlLockTable(Oid relid)
{
	HeapTuple tuple;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", relid);

    sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_TABLE,
						   TABLE__LOCK,
						   HeapTupleGetRelationName(tuple));
	ReleaseSysCache(tuple);
}

void sepgsqlAlterTableSetColumnContext(Relation rel, char *colname, Value *context)
{
	Relation pgattribute;
	HeapTuple tuple;
	psid newcon, oldcon;
	Datum datum;
	char objname[2*NAMEDATALEN + 1];

	if (!sepgsqlIsEnabled())
		selerror("SE-PostgreSQL is disabled");

	snprintf(objname, sizeof(objname), "%s/%s", RelationGetRelationName(rel), colname);

	pgattribute = heap_open(AttributeRelationId, RowExclusiveLock);

	/* lookup old security context */
	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colname);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed, column %s of relation %s",
				 colname, RelationGetRelationName(rel));
	oldcon = HeapTupleGetSecurity(tuple);

	/* lookup new security context */
	datum = DirectFunctionCall1(psid_in, CStringGetDatum(strVal(context)));
	newcon = DatumGetObjectId(datum);

	/* 1. check column:{setattr relabelfrom} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   oldcon,
						   SECCLASS_COLUMN,
						   COLUMN__SETATTR | COLUMN__RELABELFROM,
						   objname);

	/* 2. check column:{relabelto} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   newcon,
						   SECCLASS_COLUMN,
						   COLUMN__RELABELTO,
						   objname);

	/* 3. update pg_attribute->attselcon */
	HeapTupleSetSecurity(tuple, newcon);
	simple_heap_update(pgattribute, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pgattribute, tuple);

	heap_freetuple(tuple);
  	heap_close(pgattribute, RowExclusiveLock);
}

/*******************************************************************************
 * PROCEDURE related hooks
 *******************************************************************************/

static Datum sepgsqlExprStateEvalFunc(ExprState *expression,
									  ExprContext *econtext,
									  bool *isNull,
									  ExprDoneCond *isDone)
{
	Datum retval;
	psid saved_clientcon;

	/* save security context */
	saved_clientcon = sepgsqlGetClientPsid();
	sepgsqlSetClientPsid(expression->execContext);
	PG_TRY();
	{
		retval = expression->origEvalFunc(expression, econtext, isNull, isDone);
	}
	PG_CATCH();
	{
		sepgsqlSetClientPsid(saved_clientcon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	/* restore context */
	sepgsqlSetClientPsid(saved_clientcon);

	return retval;
}

void sepgsqlExecInitExpr(ExprState *state, PlanState *parent)
{
	if (!sepgsqlIsEnabled())
		return;

	switch (nodeTag(state->expr)) {
	case T_FuncExpr:
		{
			FuncExpr *func = (FuncExpr *) state->expr;
			HeapTuple tuple;
			psid execon;

			tuple = SearchSysCache(PROCOID, ObjectIdGetDatum(func->funcid), 0, 0, 0);
			if (!HeapTupleIsValid(tuple))
				selerror("RELOID cache lookup failed (pg_proc.oid=%u)", func->funcid);
			execon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   HeapTupleGetSecurity(tuple),
										   SECCLASS_PROCESS);
			if (sepgsqlGetClientPsid() != execon) {
				/* do domain transition */
				state->execContext = execon;
				state->origEvalFunc = state->evalfunc;
				state->evalfunc = sepgsqlExprStateEvalFunc;
			}
			ReleaseSysCache(tuple);
		}
		break;
	default:
		/* do nothing */
		break;
	}
}

void sepgsqlAlterProcedureContext(Relation rel, HeapTuple tuple, char *context)
{
	Datum ncon;

	if (context) {
		if (!sepgsqlIsEnabled())
			selerror("SE-PostgreSQL is disabled");

		ncon = DirectFunctionCall1(psid_in, CStringGetDatum(context));
		HeapTupleSetSecurity(tuple, DatumGetObjectId(ncon));
	}
}

/*******************************************************************************
 * COPY TO/COPY FROM related hooks
 *******************************************************************************/

void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from)
{
	HeapTuple tuple;
	uint32 perms;
	ListCell *l;

	if (!sepgsqlIsEnabled())
		return;

	/* on 'COPY FROM SELECT ...' cases, any checkings are done in select.c */
	if (rel == NULL)
		return;

	/* 1. check table:select/insert permission */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(RelationGetRelid(rel)),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));

	perms = (is_from ? TABLE__INSERT : TABLE__SELECT);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_TABLE,
						   perms,
						   HeapTupleGetRelationName(tuple));
	ReleaseSysCache(tuple);

	/* 2. check column:select/insert for each column */
	perms = (is_from ? COLUMN__INSERT : COLUMN__SELECT);
	foreach(l, attnumlist) {
		AttrNumber attno = lfirst_int(l);

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("cache lookup failed for attribute %d, relation %u",
					 attno, RelationGetRelid(rel));

		perms = (is_from ? COLUMN__INSERT : COLUMN__SELECT);
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_COLUMN,
							   perms,
							   HeapTupleGetAttributeName(tuple));
		ReleaseSysCache(tuple);
	}
}

bool sepgsqlCopyTo(Relation rel, HeapTuple tuple)
{
	if (!sepgsqlIsEnabled())
		return true;	/* always true, if disabled */

	return sepgsqlCheckTuplePerms(rel, tuple, NULL, TUPLE__SELECT, false);
}

/*******************************************************************************
 * LOAD shared library module hook
 *******************************************************************************/
void sepgsqlLoadSharedModule(const char *filename)
{
	security_context_t filecon;
	Datum filecon_psid;

	if (!sepgsqlIsEnabled())
		return;

	if (getfilecon(filename, &filecon) < 1)
		selerror("could not obtain security context of %s", filename);
	PG_TRY();
	{
		filecon_psid = DirectFunctionCall1(psid_in, CStringGetDatum(filecon));
	}
	PG_CATCH();
	{
		freecon(filecon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(filecon);

	sepgsql_avc_permission(sepgsqlGetDatabasePsid(),
						   DatumGetObjectId(filecon_psid),
						   SECCLASS_DATABASE,
						   DATABASE__LOAD_MODULE,
						   (char *) filename);
}

/*******************************************************************************
 * simple_heap_xxxx hooks
 *******************************************************************************/
static inline bool __is_simple_system_relation(Relation rel)
{
	bool retval = false;
	switch (RelationGetRelid(rel)) {
	case AttributeRelationId:
	case AuthIdRelationId:
	case DatabaseRelationId:
	case ProcedureRelationId:
	case RelationRelationId:
	case TriggerRelationId:
	case TypeRelationId:
		retval = true;
		break;
	}
	return retval;
}

void sepgsqlSimpleHeapInsert(Relation rel, HeapTuple tuple)
{
	psid ncon;

	if (!sepgsqlIsEnabled())
		return;

	if (!__is_simple_system_relation(rel))
		return;

	ncon = HeapTupleGetSecurity(tuple);
	if (ncon == InvalidOid) {
		/* no explicit labeling */
		ncon = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, ncon);
	}
	sepgsqlCheckTuplePerms(rel, tuple, NULL, TUPLE__INSERT, true);
}

void sepgsqlSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple newtup)
{
	HeapTuple oldtup;
	psid ncon, ocon;
	uint32 perms = TUPLE__UPDATE;

	if (!sepgsqlIsEnabled())
		return;

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
	psid ncon;
	uint32 perms;

	if (!sepgsqlIsEnabled())
		return true;	/* always true, if disabled */

	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("INSERT INTO pg_selinux ..., never allowed");

	ncon = HeapTupleGetSecurity(tuple);
	if (ncon == InvalidOid) {
		/* no explicit labeling */
		ncon = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, ncon);
	}
	perms = TUPLE__INSERT;
	if (with_returning)
		perms |= TUPLE__SELECT;

	return sepgsqlCheckTuplePerms(rel, tuple, NULL, perms, false);
}

bool sepgsqlExecUpdate(Relation rel, HeapTuple newtup, ItemPointer tid, bool with_returning)
{
	HeapTuple oldtup;
	psid ncon, ocon;
	uint32 perms = 0;
	bool rc;

	if (!sepgsqlIsEnabled())
		return true;	/* always true, if disabled */

	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("UPDATE pg_selinux ..., never allowed");

	oldtup = __getHeapTupleFromItemPointer(rel, tid);
	ncon = HeapTupleGetSecurity(newtup);
	ocon = HeapTupleGetSecurity(oldtup);
	if (ncon == InvalidOid) {
		HeapTupleSetSecurity(newtup, ocon);		/* keep old context */
		ocon = ncon;
	}
	if (ncon != ocon) {
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

	if (!sepgsqlIsEnabled())
		return true;	/* always true, if disabled */

	if (RelationGetRelid(rel) == SelinuxRelationId)
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
	if (!sepgsqlIsEnabled()) {
		HeapTupleSetSecurity(tuple, InvalidOid);
		return;
	}

	if (HeapTupleGetSecurity(tuple) == InvalidOid) {
		psid ncon = sepgsqlComputeImplicitContext(rel, tuple);
		HeapTupleSetSecurity(tuple, ncon);
	}
}

void sepgsqlHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	if (!sepgsqlIsEnabled()) {
		HeapTupleSetSecurity(newtup, InvalidOid);
		return;
	}

	if (HeapTupleGetSecurity(newtup) == InvalidOid) {
		psid ocon = HeapTupleGetSecurity(oldtup);
		HeapTupleSetSecurity(newtup, ocon);
	}
}
