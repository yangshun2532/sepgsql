/*
 * src/backend/security/common.c
 *    common facilities for row-level access controls both of DAC and MAC
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_security.h"
#include "security/rowlevel.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "utils/rel.h"

/*
 * rowlvGetPerformingMode
 * rowlvSetPerformingMode
 *   enables to control the behavior of row-level features
 *   when violated tuples are detected.
 *   The default is ROWLV_FILTER_MODE which filters out
 *   violated tuples from result set, ROWLV_ABORT_MODE
 *   raises an error and ROWLV_BYPASS_MODE do nothing.
 */
static int rowlv_mode = ROWLV_FILTER_MODE;

int rowlvGetPerformingMode(void)
{
	return rowlv_mode;
}

int rowlvSetPerformingMode(int new_mode)
{
	int		old_mode = new_mode;

	rowlv_mode = new_mode;

	return old_mode;
}

/*
 * rowlvSetupPermissions
 *   setups permissions for row-level access controls.
 */
#define ROWLV_PERMS_MASK		0xffff
#define ROWLV_PERMS_SHIFT		16
#define ROWLV_DAC_PERMS(perms)	((perms) & ROWLV_PERMS_MASK)
#define ROWLV_MAC_PERMS(perms)	(((perms) >> ROWLV_PERMS_SHIFT) & ROWLV_PERMS_MASK)

uint32
rowlvSetupPermissions(RangeTblEntry *rte)
{
	uint32		mac_perms;

	mac_perms = sepgsqlSetupTuplePerms(rte);
	Assert((mac_perms & ROWLV_PERMS_MASK) == mac_perms);

	return (mac_perms << ROWLV_PERMS_SHIFT);
}

/*
 * rowlvExecScan
 *   a hook to filter out invisible/untouchable tuples.
 */
static bool
rowlvExecScan(Scan *scan, Relation rel, TupleTableSlot *slot, bool abort)
{
	HeapTuple	tuple;
	uint32		perms = scan->rowlvPerms;

	tuple = ExecMaterializeSlot(slot);

	if (ROWLV_MAC_PERMS(perms) != 0 &&
		!sepgsqlExecScan(rel, tuple, ROWLV_MAC_PERMS(perms), abort))
		return false;

	return true;
}

bool
rowlvExecScanFilter(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	if (!rel || !scan->rowlvPerms || rowlv_mode != ROWLV_FILTER_MODE)
		return true;

	return rowlvExecScan(scan, rel, slot, false);
}

void
rowlvExecScanAbort(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	if (!rel || !scan->rowlvPerms || rowlv_mode != ROWLV_ABORT_MODE)
		return;

	rowlvExecScan(scan, rel, slot, true);
}

/*
 * rowlvCopyToTuple
 *   checks permission on fetched tuple
 */
bool
rowlvCopyToTuple(Relation rel, HeapTuple tuple)
{
	if (!sepgsqlExecScan(rel, tuple, SEPG_DB_TUPLE__SELECT, false))
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

	if (!sepgsqlHeapTupleDelete(rel, &oldtup, internal))
	{
		ReleaseBuffer(oldbuf);
		return false;
	}

	ReleaseBuffer(oldbuf);
	return true;
}
