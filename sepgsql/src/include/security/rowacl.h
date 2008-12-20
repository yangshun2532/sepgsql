/*
 * src/include/security/rowacl.h
 *   headers for Row-level database ACL support
 */
#ifndef ROWACL_H
#define ROWACL_H

#include "utils/acl.h"

extern void rowaclInitialize(bool is_bootstrap);

extern List *rowaclProxyQuery(List *queryList);

extern Datum rowaclBeginPerformCheckFK(Relation rel, bool is_primary, Oid userid_saved);

extern void rowaclEndPerformCheckFK(Relation rel, Datum rowacl_private);

extern bool rowaclExecScan(Scan *scan, Relation rel, TupleTableSlot *slot);

extern bool rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple);

extern bool rowaclHeapTupleInsert(Relation rel, HeapTuple tuple,
								  bool is_internal, bool with_returning);

extern bool rowaclHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
								  bool is_internal, bool with_returning);

extern bool rowaclHeapTupleDelete(Relation rel, ItemPointer otid,
								  bool is_internal, bool with_returning);

extern void rowaclGramTransformRelOptions(DefElem *defel, bool isReset);

extern bool rowaclGramParseRelOptions(const char *key, const char *value,
									  StdRdOptions *result, bool validate);

extern bool rowaclTupleDescHasRowAcl(Relation rel, List *relopts);

extern Acl *rowaclSidToSecurityAcl(Oid sid, Oid ownerId);

extern Oid rowaclSecurityAclToSid(Acl *acl);

extern Datum rowaclHeapGetSecurityAclSysattr(HeapTuple tuple);

/*
 * SQL Functions
 */


#endif  /* ROWACL_H */
