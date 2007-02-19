/*
 * src/backend/sepgsqlHooks.c
 *   SE-PostgreSQL hooks
 *
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_authid.h"
#include "catalog/pg_database.h"
#include "security/sepgsql.h"

/*
 * hooks related to CREATE/ALTER/DROP DATABASE
 */
static void __hookCreateDatabase(Relation rel, HeapTuple tuple)
{
	psid ncon = sepgsqlComputeImplicitContext(rel, tuple);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__INSERT);
}

static void __hookAlterDatabase(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	psid ncon = HeapTupleGetSecurity(newtup);
	psid ocon = HeapTupleGetSecurity(oldtup);
	uint32 perms = TUPLE__UPDATE;

	if (ncon == InvalidOid) {
		ncon = ocon;
		HeapTupleSetSecurity(newtup, ncon);
	}

	if (ncon != ocon)
		perms |= TUPLE__RELABELFROM;
	sepgsqlCheckTuplePerms(rel, oldtup, perms);

	if (ncon != ocon)
		sepgsqlCheckTuplePerms(rel, newtup, TUPLE__RELABELTO);
}

static void __hookDropDatabase(Relation rel, HeapTuple tuple)
{
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__DELETE);
}

void sepgsqlAlterDatabaseContext(Relation rel, HeapTuple tuple, char *new_context)
{
	Datum ncon;

	if (!new_context)
		return;

	ncon = DirectFunctionCall1(psid_in, CStringGetDatum(new_context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(ncon));
}


/*
 * hooks related to CREATE/ALTER/DROP ROLE
 */
static void __hookCreateRole(Relation rel, HeapTuple tuple)
{
	psid ncon = sepgsqlComputeImplicitContext(rel, tuple);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__INSERT);
}

static void __hookAlterRole(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	psid ncon = HeapTupleGetSecurity(newtup);
	psid ocon = HeapTupleGetSecurity(oldtup);
	uint32 perms = TUPLE__UPDATE;

	if (ncon == InvalidOid) {
		ncon = ocon;
		HeapTupleSetSecurity(newtup, ncon);
	}

	if (ncon != ocon)
		perms |= TUPLE__RELABELFROM;
	sepgsqlCheckTuplePerms(rel, oldtup, perms);

	if (ncon != ocon)
		sepgsqlCheckTuplePerms(rel, newtup, TUPLE__RELABELTO);
}

static void __hookDropRole(Relation rel, HeapTuple tuple)
{
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__DELETE);
}

/*
 * hooks for CREATE/ALTER/DROP FUNCTION
 */

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

void sepgsqlSimpleHeapInsert(Relation rel, HeapTuple tuple)
{
	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:
		__hookCreateDatabase(rel, tuple);
		break;
	case AuthIdRelationId:
		__hookCreateRole(rel, tuple);
		break;
	default:
		/* do nothing */
		break;
	}
}

void sepgsqlSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple newtup)
{
	HeapTuple oldtup = __getHeapTupleFromItemPointer(rel, tid);

	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:
		__hookAlterDatabase(rel, newtup, oldtup);
		break;
	case AuthIdRelationId:
		__hookAlterRole(rel, newtup, oldtup);
		break;
	default:
		/* do nothing */
		break;
	}
	heap_freetuple(oldtup);
}

void sepgsqlSimpleHeapDelete(Relation rel, ItemPointer tid)
{
	HeapTuple tuple = __getHeapTupleFromItemPointer(rel, tid);

	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:
		__hookDropDatabase(rel, tuple);
		break;
	case AuthIdRelationId:
		__hookDropRole(rel, tuple);
		break;
	default:
		/* do nothing */
		break;
	}
	heap_freetuple(tuple);
}
