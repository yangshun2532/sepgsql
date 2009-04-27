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

extern AclMode
rowlvSetupPermissions(RangeTblEntry *rte);

extern bool
rowlvExecScan(Scan *scan, Relation rel, TupleTableSlot *slot);

extern bool
rowlvHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal);

extern bool
rowlvHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup, bool internal);

extern bool
rowlvHeapTupleDelete(Relation rel, ItemPointer otid, bool internal);

extern bool
rowlvCopyToTuple(Relation rel, HeapTuple tuple);

#endif	/* ROWLEVEL_H */
