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
 * hooks for generic DATABASE objects
 */
static void __hookCreateGenericDatabaseObject(Relation rel, HeapTuple tuple)
{
	psid ncon = sepgsqlComputeImplicitContext(rel, tuple);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__INSERT, true);
}

static void __hookAlterGenericDatabaseObject(Relation rel, HeapTuple newtup, HeapTuple oldtup)
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
	sepgsqlCheckTuplePerms(rel, oldtup, perms, true);

	if (ncon != ocon)
		sepgsqlCheckTuplePerms(rel, newtup, TUPLE__RELABELTO, true);
}

static void __hookDropGenericDatabaseObject(Relation rel, HeapTuple tuple)
{
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__DELETE, true);
}

/*
 * for ALTER DATABASE <dbname> CONTEXT = 'security context'; statement
 */
void sepgsqlAlterDatabaseContext(Relation rel, HeapTuple tuple, char *new_context)
{
	Datum ncon;

	if (!new_context)
		return;

	ncon = DirectFunctionCall1(psid_in, CStringGetDatum(new_context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(ncon));
}

/*
 * for COPY TO/COPY FROM statement support
 */
void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from)
{
	HeapTuple tuple;
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
		char objname[2 * NAMEDATALEN + 1];
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
	return sepgsqlCheckTuplePerms(rel, tuple, TUPLE__SELECT, false);
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
	case AuthIdRelationId:
	case DatabaseRelationId:
		__hookCreateGenericDatabaseObject(rel, tuple);
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
	case AuthIdRelationId:
	case DatabaseRelationId:
		__hookAlterGenericDatabaseObject(rel, newtup, oldtup);
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
	case AuthIdRelationId:
	case DatabaseRelationId:
		__hookDropGenericDatabaseObject(rel, tuple);
		break;
	default:
		/* do nothing */
		break;
	}
	heap_freetuple(tuple);
}
