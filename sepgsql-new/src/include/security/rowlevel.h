/*
 * src/include/security/rowlevel.h
 *    Definition of the facility of row-level access controls
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef ROWLEVEL_H
#define ROWLEVEL_H

#include "access/htup.h"
#include "executor/tuptable.h"
#include "nodes/plannodes.h"
#include "utils/relcache.h"

#define ROWLV_BYPASS_MODE   1
#define ROWLV_FILTER_MODE   2
#define ROWLV_ABORT_MODE    3

extern int
rowlvGetPerformingMode(void);

extern int
rowlvSetPerformingMode(int mode);

extern uint32
rowlvSetupPermissions(RangeTblEntry *rte);

extern bool
rowlvExecScanFilter(Scan *scan, Relation rel, TupleTableSlot *slot);

extern void
rowlvExecScanAbort(Scan *scan, Relation rel, TupleTableSlot *slot);

extern bool
rowlvHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal);

extern bool
rowlvHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup, bool internal);

extern bool
rowlvHeapTupleDelete(Relation rel, ItemPointer otid, bool internal);

extern bool
rowlvCopyToTuple(Relation rel, HeapTuple tuple);

#endif   /* PG_SELINUX_H */
