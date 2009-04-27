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
	AclMode		dac_perms, mac_perms;

	dac_perms = rowaclSetupTuplePerms(rte);
	Assert((dac_perms & ROWLV_PERMS_MASK) == dac_perms);

	mac_perms = sepgsqlSetupTuplePerms(rte);
	Assert((mac_perms & ROWLV_PERMS_MASK) == mac_perms);

	return (mac_perms << ROWLV_PERMS_SHIFT) | dac_perms;
}

/*
 * rowlvExecScan
 *   a hook to filter out invisible/untouchable tuples.
 */
bool
rowlvExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{
	HeapTuple		tuple;
	uint32			perms = scan->rowlvPerms;

	/* skip row-level checks on not-general relation */
	if (!rel || !perms)
		return true;

	tuple = ExecMaterializeSlot(slot);

	if (ROWLV_DAC_PERMS(perms) != 0 &&
		!rowaclExecScan(rel, tuple, ROWLV_DAC_PERMS(perms)))
		return false;

	if (ROWLV_MAC_PERMS(perms) != 0 &&
		!sepgsqlExecScan(rel, tuple, ROWLV_MAC_PERMS(perms)))
		return false;

	return true;
}

/*
 * rowlvCopyToTuple
 *   checks permission on fetched tuple
 */
bool
rowlvCopyToTuple(Relation rel, HeapTuple tuple)
{
	if (!rowaclExecScan(rel, tuple, ACL_SELECT))
		return false;
	if (!sepgsqlExecScan(rel, tuple, SEPG_DB_TUPLE__SELECT))
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
