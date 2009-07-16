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
#define ROWLV_PERMS_MASK		0xffff
#define ROWLV_PERMS_SHIFT		16
#define ROWLV_DAC_PERMS(perms)	((perms) & ROWLV_PERMS_MASK)
#define ROWLV_MAC_PERMS(perms)	(((perms) >> ROWLV_PERMS_SHIFT) & ROWLV_PERMS_MASK)

uint32
rowlvSetupPermissions(RangeTblEntry *rte)
{
	uint32		dac_perms, mac_perms;

	dac_perms = 0;	/* upcoming Row-level ACLs */
	mac_perms = sepgsqlSetupTuplePerms(rte);
	Assert((mac_perms & ROWLV_PERMS_MASK) == mac_perms);

	return (mac_perms << ROWLV_PERMS_SHIFT) | dac_perms;
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
