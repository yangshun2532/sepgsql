/*
 * src/include/security/rowacl.h
 *    headers for row-level access controls
 */
#ifndef ROWACL_H
#define ROWACL_H

extern bool rowaclIsEnabled(void);

/*
 * row-level filtering when reading it
 */
extern bool rowaclExecScan(Scan *scan,
						   Relation rel,
						   TupleTableSlot *slot);
extern bool rowaclCopyToTuple(Relation rel,
							  List *attNumList,
							  HeapTuple tuple);
/*
 * hooks when tuples are modified
 */
extern bool rowaclHeapTupleInsert(Relation rel,
								  HeapTuple tuple,
								  bool is_internal,
								  bool with_returning);
extern bool rowaclHeapTupleUpdate(Relation rel,
								  ItemPointer otid,
								  HeapTuple newtup,
								  bool is_internal,
								  bool with_returning);
extern bool rowaclHeapTupleDelete(Relation rel,
								  ItemPointer otid,
								  bool is_internal,
								  bool with_returning);
/*
 * special handling for PK/FK constraints
 */
extern void rowaclBeginPerformCheckFK(Relation rel,
									  bool rel_is_primary,
									  Datum *save_pgace);
extern void rowaclEndPerformCheckFK(Relation rel,
									bool rel_is_primary,
									Datum save_pgace);
/*
 * ACL handler
 */
extern char *rowaclValidateSecurityLabel(char *seclabel);

#endif
