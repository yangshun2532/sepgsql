/*
 * src/include/security/row_acl.h
 *    headers for Row-level ACL support
 */
#ifndef ROW_ACL_H
#define ROW_ACL_H

extern bool rowacl_is_enabled_mode;

extern bool rowaclIsEnabled(void);

extern void rowaclInitialize(bool is_bootstrap);

/******************************************************************
 * Row-level access controls
 ******************************************************************/
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

/******************************************************************
 * Default ACL support
 ******************************************************************/

extern DefElem *rowaclGramSecurityItem(char *defname, char *value);

extern bool rowaclIsGramSecurityItem(DefElem *defel);

extern void rowaclGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel);

extern void rowaclGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel);

/******************************************************************
 * Security Label hooks
 ******************************************************************/

extern bool rowaclSecurityAttributeNecessary(void);

extern char *rowaclTranslateSecurityLabelIn(char *seclabel);

extern char *rowaclTranslateSecurityLabelOut(char *seclabel);

extern bool rowaclCheckValidSecurityLabel(char *seclabel);

extern char *rowaclUnlabeledSecurityLabel(void);

extern char *rowaclSecurityLabelOfLabel(void);

/******************************************************************
 * SQL functions
 ******************************************************************/

extern Datum rowacl_grant(PG_FUNCTION_ARGS);

extern Datum rowacl_revoke(PG_FUNCTION_ARGS);

extern Datum rowacl_revoke_cascade(PG_FUNCTION_ARGS);

#endif	/* ROW_ACL_H */
