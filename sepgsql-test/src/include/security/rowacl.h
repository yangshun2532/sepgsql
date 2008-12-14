/*
 * src/include/security/rowacl.h
 *   headers for Row-level database ACL support
 */
#ifndef ROWACL_H
#define ROWACL_H

/*
 * Functions for Management of security identifier/text representaion
 */

extern bool rowaclTupleDescHasSecurity(Relation rel, List *relopts);

/*
 * Functions for Row-level access controls
 */
extern List *rowaclProxyQuery(List *queryList);

extern bool rowaclExecScan(Scan *scan, Relation rel, TupleTableSlot *slot);

extern bool rowaclHeapTupleInsert(Relation rel, HeapTuple tuple,
								  bool is_internal, bool with_returning);

extern bool rowaclHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
								  bool is_internal, bool with_returning);

extern bool rowaclHeapTupleDelete(Relation rel, ItemPointer otid,
								  bool is_internal, bool with_returning);

extern bool rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple);

extern Datum rowaclBeginPerformCheckFK(Relation rel, bool is_primary, Oid save_userid);

extern void rowaclEndPerformCheckFK(Relation rel, Datum save_pgace);

#endif  /* ROWACL_H */




