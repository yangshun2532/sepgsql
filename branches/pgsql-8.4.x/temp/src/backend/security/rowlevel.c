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
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "storage/bufpage.h"
#include "utils/rel.h"
#include "utils/tqual.h"

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
uint32
rowlvSetupPermissions(RangeTblEntry *rte)
{
	return sepgsqlSetupTuplePerms(rte);
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

	if (!perms)
		return true;

	tuple = ExecMaterializeSlot(slot);

	return sepgsqlExecScan(rel, tuple, perms, abort);
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
 *   assign default security attribute, and check permission
 *   if necessary.
 */
void
rowlvHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal)
{
	sepgsqlHeapTupleInsert(rel, newtup, internal);
}

/*
 * rowlvHeapTupleUpdate
 *   check permission to change security attribute, if necesary
 */
void
rowlvHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup)
{
	sepgsqlHeapTupleUpdate(rel, otid, newtup);
}
