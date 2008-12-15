/*
 * src/include/security/rowacl.h
 *   headers for Row-level database ACL support
 */
#ifndef ROWACL_H
#define ROWACL_H

#include "utils/acl.h"

/*
 * Management of row-level ACLs
 */
extern bool rowaclTupleDescHasSecurity(Relation rel, List *relopts);

extern Acl *rowaclSidToSecurityAcl(Oid sid, Oid ownerId);

extern Oid rowaclSecurityAclToSid(Acl *acl);

extern Datum rowaclHeapGetSecurityAclSysattr(HeapTuple tuple);

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




