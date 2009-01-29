/*
 * src/include/sepgsql.h
 *    The header file of Security Enhanced PostgreSQL
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H
#include "executor/executor.h"
#include "security/sepgsql_internal.h"
#include "utils/portal.h"

#define SECURITY_SYSATTR_NAME		"security_context"

/******************************************************************
 * Initialize / Finalize related hooks
 ******************************************************************/

static inline Size pgaceShmemSize(void) {
	Size retval = 0;
	if (sepgsqlIsEnabled())
		retval = sepgsqlShmemSize();
	return retval;
}

static inline void pgaceInitialize(void) {
	if (sepgsqlIsEnabled())
		sepgsqlInitialize();
}

static inline bool pgaceInitializePostmaster(void) {
	if (!sepgsqlIsEnabled())
		return true;
	return sepgsqlInitializePostmaster();
}

static inline void pgaceFinalizePostmaster(void) {
	if (!sepgsqlIsEnabled())
		return;
	sepgsqlFinalizePostmaster();
}

/******************************************************************
 * SQL proxy hooks
 ******************************************************************/

static inline List *pgaceProxyQuery(List *queryList) {
	List *newList = NIL;
	ListCell *l;

	if (!sepgsqlIsEnabled())
		return queryList;
	foreach (l, queryList) {
		Query *query = (Query *) lfirst(l);

		newList = list_concat(newList, sepgsqlProxyQuery(query));
	}
	return newList;
}

static inline void pgacePortalStart(Portal portal) {
	/* do nothing */
}

static inline void pgaceExecutorStart(QueryDesc *queryDesc, int eflags) {
	if (!sepgsqlIsEnabled() || (eflags & EXEC_FLAG_EXPLAIN_ONLY))
		return;

	Assert(queryDesc->parsetree != NULL);
	sepgsqlVerifyQuery(queryDesc->parsetree);
}

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/

static inline bool pgaceExecInsert(Relation rel, HeapTuple tuple, bool with_returning) {
	if (!sepgsqlIsEnabled())
		return true;
	return sepgsqlExecInsert(rel, tuple, with_returning);
}

static inline bool pgaceExecUpdate(Relation rel, HeapTuple newtup, ItemPointer tid, bool with_returning) {
	if (!sepgsqlIsEnabled())
		return true;
	return sepgsqlExecUpdate(rel, newtup, tid, with_returning);
}

static inline bool pgaceExecDelete(Relation rel, ItemPointer tid, bool with_returning) {
	if (!sepgsqlIsEnabled())
		return true;
	return sepgsqlExecDelete(rel, tid, with_returning);
}

static inline void pgaceSimpleHeapInsert(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlSimpleHeapInsert(rel, tuple);
}

static inline void pgaceSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlSimpleHeapUpdate(rel, tid, tuple);
}

static inline void pgaceSimpleHeapDelete(Relation rel, ItemPointer tid) {
	if (sepgsqlIsEnabled())
		sepgsqlSimpleHeapDelete(rel, tid);
}

static inline void pgaceHeapInsert(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlHeapInsert(rel, tuple);
}

static inline void pgaceHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup) {
	if (sepgsqlIsEnabled())
		sepgsqlHeapUpdate(rel, newtup, oldtup);
}

static inline void pgaceHeapDelete(Relation rel, HeapTuple oldtup) {
	/* do nothing */
}

/******************************************************************
 * Extended SQL statement hooks
 ******************************************************************/
static inline DefElem *pgaceGramSecurityLabel(char *defname, char *value) {
	if (!sepgsqlIsEnabled())
		return NULL;
	return sepgsqlGramSecurityLabel(defname, value);
}

static inline bool pgaceNodeIsSecurityLabel(DefElem *defel) {
	if (!sepgsqlIsEnabled())
		return false;
	return sepgsqlNodeIsSecurityLabel(defel);
}

static inline Oid pgaceParseSecurityLabel(DefElem *defel) {
	if (sepgsqlIsEnabled() && defel)
		return sepgsqlParseSecurityLabel(defel);
	return InvalidOid;
}

/******************************************************************
 * DATABASE related hooks
 ******************************************************************/

static inline void pgaceSetDatabaseParam(const char *name, char *argstring) {
	/* argstring == NULL means set default */
	if (sepgsqlIsEnabled())
		sepgsqlSetDatabaseParam(name, argstring);
}

static inline void pgaceGetDatabaseParam(const char *name) {
	if (sepgsqlIsEnabled())
		sepgsqlGetDatabaseParam(name);
}

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/

static inline void pgaceCallFunction(FmgrInfo *finfo) {
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, false);
}

static inline bool pgaceCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata) {
	if (!sepgsqlIsEnabled())
		return true;
	return sepgsqlCallFunctionTrigger(finfo, tgdata);
}

static inline void pgaceCallFunctionFastPath(FmgrInfo *finfo) {
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, true);
}

static inline Datum pgacePreparePlanCheck(Relation rel) {
	Oid pgace_saved = InvalidOid;
	if (sepgsqlIsEnabled())
		pgace_saved = sepgsqlPreparePlanCheck(rel);
	return ObjectIdGetDatum(pgace_saved);
}

static inline void pgaceRestorePlanCheck(Relation rel, Datum pgace_saved) {
	if (sepgsqlIsEnabled())
		sepgsqlRestorePlanCheck(rel, DatumGetObjectId(pgace_saved));
}

/******************************************************************
 * TABLE related hooks
 ******************************************************************/

static inline void pgaceLockTable(Oid relid) {
	if (sepgsqlIsEnabled())
		sepgsqlLockTable(relid);
}

/******************************************************************
 * COPY TO/COPY FROM statement hooks
 ******************************************************************/

static inline void pgaceCopyTable(Relation rel, List *attNumList, bool isFrom) {
	if (sepgsqlIsEnabled())
		sepgsqlCopyTable(rel, attNumList, isFrom);
}

static inline bool pgaceCopyToTuple(Relation rel, HeapTuple tuple) {
	if (!sepgsqlIsEnabled())
		return true;
	return sepgsqlCopyToTuple(rel, tuple);
}

static inline bool pgaceCopyFromTuple(Relation rel, HeapTuple tuple) {
	if (!sepgsqlIsEnabled())
		return true;
	return sepgsqlCopyFromTuple(rel, tuple);
}

/******************************************************************
 * Loadable shared library module hooks
 ******************************************************************/

static inline void pgaceLoadSharedModule(const char *filename) {
	if (sepgsqlIsEnabled())
		sepgsqlLoadSharedModule(filename);
}

/******************************************************************
 * Binary Large Object (BLOB) hooks
 ******************************************************************/
static inline Oid pgaceLargeObjectGetSecurity(HeapTuple tuple) {
	if (!sepgsqlIsEnabled())
		selerror("SELinux is disabled");
	return sepgsqlLargeObjectGetSecurity(tuple);
}

static inline void pgaceLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectSetSecurity(tuple, lo_security, is_first);
}

static inline void pgaceLargeObjectCreate(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectCreate(rel, tuple);
}

static inline void pgaceLargeObjectDrop(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectDrop(rel, tuple);
}

static inline void pgaceLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectOpen(rel, tuple, read_only);
}

static inline void pgaceLargeObjectRead(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectRead(rel, tuple);
}

static inline void pgaceLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectWrite(rel, newtup, oldtup);
}

static inline void pgaceLargeObjectImport(void) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectImport();
}

static inline void pgaceLargeObjectExport(void) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectExport();
}

/******************************************************************
 * Security Label hooks
 ******************************************************************/
static inline char *pgaceSecurityLabelIn(char *context) {
	if (!sepgsqlIsEnabled())
		return NULL;
	return sepgsqlSecurityLabelIn(context);
}

static inline char *pgaceSecurityLabelOut(char *context) {
	if (!sepgsqlIsEnabled())
		return NULL;
	return sepgsqlSecurityLabelOut(context);
}

static inline bool pgaceSecurityLabelIsValid(char *context) {
	if (!sepgsqlIsEnabled())
		return false;
	return sepgsqlSecurityLabelIsValid(context);
}

static inline char *pgaceSecurityLabelOfLabel(char *new_label) {
	if (!sepgsqlIsEnabled())
		return pstrdup("unlabeled");
	return sepgsqlSecurityLabelOfLabel(new_label);
}

static inline char *pgaceSecurityLabelNotFound(Oid sid) {
	if (!sepgsqlIsEnabled())
		return pstrdup("unlabeled");

	return sepgsqlSecurityLabelNotFound(sid);
}

/******************************************************************
 * Extended node type hooks
 ******************************************************************/

static inline Node *pgaceCopyObject(Node *orig) {
	if (!sepgsqlIsEnabled())
		return NULL;
	return sepgsqlCopyObject(orig);
}

static inline bool pgaceOutObject(StringInfo str, Node *node) {
	if (!sepgsqlIsEnabled())
		return false;
	return sepgsqlOutObject(str, node);
}

#endif /* SEPGSQL_H */