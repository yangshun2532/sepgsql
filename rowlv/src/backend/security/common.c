/*
 * src/backend/security/common.c
 *    common facilities for row-level access controls both of DAC and MAC
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_security.h"
#include "security/rowacl.h"
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "utils/rel.h"

/*
 * securityGetRowLevelStrategy()
 * securitySetRowLevelStrategy()
 *
 *   controls how row-level security features works.
 *   When the securityRowLevelStrategy is 'false', it filtered out
 *   the violated tuples from the result set. Otherwise, it raises
 *   an error to stop query execution.
 *   It should be switched to 'true' during FK constraint checks.
 */
static bool securityRowLevelStrategy = false;

bool
securityGetRowLevelStrategy(void)
{
	return securityRowLevelStrategy;
}

bool
securitySetRowLevelStrategy(bool new_strategy)
{
	bool	old_strategy = securityRowLevelStrategy;

	securityRowLevelStrategy = new_strategy;

	return old_strategy;
}

/*
 * securityExecScan
 *
 *   is invoked from ExecScan() to check visibility of fetched tuple
 *   via row-level security features. When it returns false, the given
 *   tuple is filtered out from the result set.
 */
bool
securityExecScan(Scan *scan, Relation relation, TupleTableSlot *slot)
{
	HeapTuple	tuple;
	AclMode		required;

	/*
	 * If no permissions are required to be checked, it simply
	 * allows to fetch it from the relation.
	 */
	if (!scan->tuple_perms)
		return true;

	tuple = ExecMaterializeSlot(slot);

	/*
	 * Row-level ACLs reserves lower N_ACL_RIGHTS bits
	 * to represent its permissions.
	 */
	required = (scan->tuple_perms & ((1UL<<N_ACL_RIGHTS) - 1));
	if (required && !rowaclExecScan(relation, tuple, required))
		return false;

	/*
	 * SE-PostgreSQL reserves rest of bits in tuple_perms
	 * to represent its permissions.
	 */
	//required = (scan->tuple_perms & ~((1UL<<N_ACL_RIGHTS) - 1));
	//if (required && sepgsqlExecScan(relation, tuple, required))
	//	return false;

	return true;
}

/*
 * get_older_tuple
 *   returns a copied HeapTuple required by ItemPointer
 */
static HeapTuple
get_older_tuple(Relation rel, ItemPointer otid)
{
	Buffer			buffer;
	PageHeader		dp;
	ItemId			lp;
	HeapTupleData	tuple;
	HeapTuple		oldtup;

	buffer = ReadBuffer(rel, ItemPointerGetBlockNumber(otid));
	LockBuffer(buffer, BUFFER_LOCK_SHARE);

	dp = (PageHeader) BufferGetPage(buffer);
	lp = PageGetItemId(dp, ItemPointerGetOffsetNumber(otid));

	Assert(ItemIdIsNormal(lp));

	tuple.t_data = (HeapTupleHeader) PageGetItem((Page) dp, lp);
	tuple.t_len = ItemIdGetLength(lp);
	tuple.t_self = *otid;
	tuple.t_tableOid = RelationGetRelid(rel);
	oldtup = heap_copytuple(&tuple);

	LockBuffer(buffer, BUFFER_LOCK_UNLOCK);
	ReleaseBuffer(buffer);

	return oldtup;
}

/*
 * securityHeapTupleInsert
 *   checks INSERT permission on the given tuple.
 */
bool
securityHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	if (!rowaclHeapTupleInsert(rel, newtup, internal))
		return false;

	// if (!sepgsqlHeapTupleInsert(rel, newtup, internal))
	//	return false;

	return true;
}

/*
 * securityHeapTupleUpdate
 *   checks UPDATE permission on the given tuple.
 */
bool
securityHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup, bool internal)
{
	HeapTuple	oldtup = get_older_tuple(rel, otid);

	if (!rowaclHeapTupleUpdate(rel, newtup, oldtup, internal))
		return false;

	// if (!sepgsqlHeapTupleUpdate(rel, newtup, oldtup, internal))
	//	return false;

	heap_freetuple(oldtup);

	return true;
}

/*
 * securityHeapTupleDelete
 *   checks DELETE permission on the given tuple.
 */
bool
securityHeapTupleDelete(Relation rel, ItemPointer otid, bool internal)
{
	HeapTuple	oldtup = get_older_tuple(rel, otid);

	if (!rowaclHeapTupleDelete(rel, oldtup, internal))
		return false;

	// if (!sepgsqlHeapTupleDelete(rel, oldtup, internal))
	//	return false;

	heap_freetuple(oldtup);

	return true;
}
