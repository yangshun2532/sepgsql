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
#include "utils/tqual.h"

/*
 * rowlvBehaviorSwitchTo
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
static bool rowlvAbortBehavior = false;

bool
rowlvBehaviorSwitchTo(bool new_abort)
{
	bool	old_abort = rowlvAbortBehavior;

	rowlvAbortBehavior = new_abort;

	return old_abort;
}

/*
 * rowlvExecScan
 *   a hook to filter out invisible/untouchable tuples.
 */
bool
rowlvExecScan(Scan *scan, Relation rel, TupleTableSlot *slot, bool abort)
{
	HeapTuple		tuple;
	AclMode			required = scan->requiredPerms;
	Oid				checkAsUser = scan->checkAsUser;

	/* It is not a time to make a decision */
	if (rowlvAbortBehavior != abort)
		return true;

	/* skip row-level controls on virtual relation */
	if (!rel)
		return true;

	tuple = ExecMaterializeSlot(slot);

	if (!rowaclExecScan(rel, tuple, required, checkAsUser, abort))
		return false;

	if (!sepgsqlExecScan(rel, tuple, required, abort))
		return false;

	return true;
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
	{
		Assert(!internal);
		return false;
	}

	if (!sepgsqlHeapTupleInsert(rel, newtup, internal))
	{
		Assert(!internal);
		return false;
	}

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
	HeapTupleData	oldtup;
	Buffer			oldbuf;

	ItemPointerCopy(otid, &oldtup.t_self);
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "failed to fetch a tuple for row-level access controls");

	if (!rowaclHeapTupleUpdate(rel, &oldtup, newtup, internal))
	{
		ReleaseBuffer(oldbuf);
		return false;
	}

	if (!sepgsqlHeapTupleUpdate(rel, &oldtup, newtup, internal))
	{
		ReleaseBuffer(oldbuf);
		return false;
	}

	ReleaseBuffer(oldbuf);
	return true;
}

/*
 * rowlvHeapTupleDelete
 *   checks permissions on delete a tuple.
 */
bool
rowlvHeapTupleDelete(Relation rel, ItemPointer otid, bool internal)
{
	HeapTupleData	oldtup;
	Buffer			oldbuf;

	ItemPointerCopy(otid, &oldtup.t_self);
	if (!heap_fetch(rel, SnapshotAny, &oldtup, &oldbuf, false, NULL))
		elog(ERROR, "failed to fetch a tuple for row-level access controls");

	if (!rowaclHeapTupleDelete(rel, &oldtup, internal))
	{
		ReleaseBuffer(oldbuf);
		return false;
	}

	if (!sepgsqlHeapTupleDelete(rel, &oldtup, internal))
	{
		ReleaseBuffer(oldbuf);
		return false;
	}

	ReleaseBuffer(oldbuf);
	return true;
}

/*
 * rowlvCopyToTuple
 *   checks permission on fetched tuple
 */
bool
rowlvCopyToTuple(Relation rel, HeapTuple tuple)
{
	AclMode		required = ACL_SELECT;

	if (!rowaclExecScan(rel, tuple, required, InvalidOid, false))
		return false;

	if (!sepgsqlExecScan(rel, tuple, required, false))
		return false;

	return true;
}
