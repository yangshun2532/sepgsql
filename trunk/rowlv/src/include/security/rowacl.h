#ifndef ROWACL_H
#define ROWACL_H

#include "catalog/pg_security.h"

extern void rowaclInitialize(void);
extern bool rowaclExecScan(Relation rel, HeapTuple tuple,
						   AclMode required, Oid checkAsUser, bool abort);
extern bool rowaclCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple);
extern void rowaclValidateDefaultRowAclRelopt(char *value);
extern bool rowaclTupleDescHasRowAcl(Relation rel);
extern bool rowaclInterpretRowAclOption(List *relopts);
extern bool rowaclHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal);
extern bool rowaclHeapTupleUpdate(Relation rel, HeapTuple oldtup, HeapTuple newtup, bool internal);
extern bool rowaclHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal);

#endif	/* ROWACL_H */
