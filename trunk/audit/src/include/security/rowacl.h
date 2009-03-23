/*
 * src/include/security/rowacl.h
 *    Definition of the Row-level Database ACLs
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef ROWACL_H
#define ROWACL_H

#include "access/htup.h"
#include "nodes/parsenodes.h"
#include "utils/relcache.h"

extern void
rowaclInitialize(void);

extern bool
rowaclExecScan(Relation rel, HeapTuple tuple,
			   AclMode required, Oid checkAsUser, bool abort);

extern void
rowaclReloptDefaultRowAcl(char *value);

extern bool
rowaclTupleDescHasRowAcl(Relation rel);

extern bool
rowaclInterpretRowAclOption(List *relopts);

extern bool
rowaclHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal);

extern bool
rowaclHeapTupleUpdate(Relation rel, HeapTuple oldtup, HeapTuple newtup, bool internal);

extern bool
rowaclHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal);

#endif	/* ROWACL_H */



