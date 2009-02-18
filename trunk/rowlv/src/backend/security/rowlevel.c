/*
 * src/backend/security/common.c
 *    common facilities for row-level access controls both of DAC and MAC
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_security.h"
#include "security/rowlevel.h"
#include "security/rowacl.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "utils/rel.h"

/*
 * rowlvStrategySwitchTo
 *
 *   switches current behavior of the row level access control features.
 *   In the default, it works as a filter to skip fetching violated tuples
 *   at the ExecScan(). However, we should not apply simple filtering
 *   policy at a few exceptions, during checks of FK constraints.
 *
 *   PostgreSQL implements FK constraints as trigger functions.
 *   When we update or delete tuples within PK table, these triggers are
 *   invoked to check FK tables whether the mofified PK is refered, or not.
 *   In this case, we have to consider a possibility one or more invisible
 *   or untouchable tuples are refering the target PK. If we simply filter
 *   out these tuples in this case, it allows to delete refered PKs, keep
 *   the current value of FK on SET CASCADE rules, and so on.
 *
 *   So, it is necessary to raise an error when invisible or untouchable
 *   ones are refering PKs. It also makes another issues.
 *   In the filtering strategy, any permission checks are done earlier
 *   than evaluations of WHERE clause, because user can give a malicious
 *   function as a condition with side effects which allows to expose
 *   the contents of invisible tuples.
 *   However, when we adopt a strategy of "abort on violation", permission
 *   should be checked after the evaluation of WHERE clause, because it
 *   raises an error even if the given tuple is out of scopes. In this case,
 *   we have an assumption that WHERE clause is not malicious and does not
 *   has side effect.
 *   The built-in FK constraints always uses simple operators which are
 *   already cheked on installation both of database ACL and SELinux.
 *   So, it is possible to change the behavior during FK constraint.
 *   Elsewhere, we should apply filtering strategy, as far as we cannot
 *   ensure a malicious function is injected on WHERE clause.
 */
static bool rowlvCurrentStrategy = false;

bool
rowlvStrategySwitchTo(bool new_stg)
{
	bool	old_stg = rowlvCurrentStrategy;

	rowlvCurrentStrategy = new_stg;

	return old_stg;
}

/*
 * rowlvExecScan
 *   a hook to filter out invisible/untouchable tuples.
 */
bool
rowlvExecScan(Scan *scan, Relation rel, TupleTableSlot *slot, bool abort)
{
	HeapTuple		tuple;
	AclMode			required;

	if (rowlvCurrentStrategy != abort)
		return true;

	/*
	 * If no permissions are required to be checked, it always allow
	 * to fetch the given tuples.
	 */
	if (!scan->tuplePerms)
		return true;

	tuple = ExecMaterializeSlot(slot);

	/*
	 * Row-level database ACLs (DAC feature)
	 */
	required = (scan->tuplePerms & ACL_ALL_RIGHTS);
	if (required && !rowaclExecScan(rel, tuple, required, abort))
	{
		Assert(abort == false);
		return false;
	}

	/*
	 * SE-PostgreSQL (MAC feature)
	 */
	required = (scan->tuplePerms & ~ACL_ALL_RIGHTS);
	if (required && !sepgsqlExecScan(rel, tuple, required, abort))
	{
		Assert(abort == false);
		return false;
	}

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
 * rowlvHeapTupleInsert
 *   assigns default acl and label on a newly inserted tuple, and checks
 *   permissions on insert a tuple.
 */
bool
rowlvHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	if (!rowaclHeapTupleInsert(rel, newtup, internal))
		return false;

	if (!sepgsqlHeapTupleInsert(rel, newtup, internal))
		return false;

	return true;
}

/*
 * rowlvHeapTupleUpdate
 *   preserves original acl and label if necessary, and checks
 *   permissions on update a tuple.
 */
bool
rowlvHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup, bool internal)
{
	HeapTuple	oldtup = get_older_tuple(rel, otid);

	if (!rowaclHeapTupleUpdate(rel, newtup, oldtup, internal))
		return false;

	if (!sepgsqlHeapTupleUpdate(rel, newtup, oldtup, internal))
		return false;

	return true;
}

/*
 * rowlvHeapTupleDelete
 *   checks permissions on delete a tuple.
 */
bool
rowlvHeapTupleDelete(Relation rel, ItemPointer otid, bool internal)
{
	HeapTuple	oldtup = get_older_tuple(rel, otid);

	if (!rowaclHeapTupleDelete(rel, oldtup, internal))
		return false;

	if (!sepgsqlHeapTupleDelete(rel, oldtup, internal))
		return false;

	return true;
}

/*
 * rowlvCopyToTuple
 *   checks permission on fetched tuple
 */
bool
rowlvCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
	if (!rowaclCopyToTuple(rel, attNumList, tuple))
		return false;

	if (!sepgsqlCopyToTuple(rel, attNumList, tuple))
		return false;

	return true;
}
