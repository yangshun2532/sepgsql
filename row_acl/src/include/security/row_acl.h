/*
 * src/include/security/row_acl.h
 *    headers for Row-level ACL support
 */
#ifndef ROW_ACL_H
#define ROW_ACL_H


extern bool rowaclIsEnabled(void);

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

extern void rowaclBeginPerformCheckFK(Relation rel, bool rel_is_primary,
				      Datum *save_pgace);

extern void rowaclEndPerformCheckFK(Relation rel, bool rel_is_primary,
				    Datum save_pgace);

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

#define ROW_ACL_EMPTY_STRING		"__no_acl__"

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
