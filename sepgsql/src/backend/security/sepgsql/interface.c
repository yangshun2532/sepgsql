/*
 * src/backend/security/sepgsql/interface.c
 *   SE-PostgreSQL/PGACE Interfaces
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "executor/executor.h"
#include "security/pgace.h"
#include "security/sepgsql.h"

/******************************************************************
 * Initialize / Finalize related hooks
 ******************************************************************/
Size pgaceShmemSize(void)
{
	if (sepgsqlIsEnabled())
		return sepgsqlShmemSize();
	return (Size) 0;
}

void pgaceInitialize(bool is_bootstrap)
{
	if (sepgsqlIsEnabled())
		sepgsqlInitialize(is_bootstrap);
}

bool pgaceInitializePostmaster(void)
{
	if (sepgsqlIsEnabled())
		return sepgsqlInitializePostmaster();
	return true;
}

void pgaceFinalizePostmaster(void)
{
	if (sepgsqlIsEnabled())
		sepgsqlFinalizePostmaster();
}

/******************************************************************
 * SQL proxy hooks
 ******************************************************************/
List *pgaceProxyQuery(List *queryList)
{
	List *newList = NIL;
	ListCell *l;

	if (sepgsqlIsEnabled()) {
		foreach (l, queryList) {
			Query *q = (Query *) lfirst(l);

			newList = list_concat(newList, sepgsqlProxyQuery(q));
		}
		queryList = newList;
	}
	return queryList;
}

void pgacePortalStart(Portal portal)
{
	/* do nothing */
}

void pgaceExecutorStart(QueryDesc *queryDesc, int eflags)
{
	if (sepgsqlIsEnabled() && !(eflags & EXEC_FLAG_EXPLAIN_ONLY)) {
		Assert(queryDesc->plannedstmt != NULL);
		sepgsqlVerifyQuery(queryDesc->plannedstmt);
	}
}

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/
bool pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
						  bool is_internal, bool with_returning)
{
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleInsert(rel, tuple, is_internal, with_returning);
	return true;
}

bool pgaceHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
						  bool is_internal, bool with_returning)
{
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleUpdate(rel, otid, newtup, is_internal, with_returning);
	return true;
}

bool pgaceHeapTupleDelete(Relation rel, ItemPointer otid,
						  bool is_internal, bool with_returning)
{
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleDelete(rel, otid, is_internal, with_returning);
	return true;
}

/******************************************************************
 * Extended SQL statement hooks
 ******************************************************************/
DefElem *pgaceGramSecurityItem(char *defname, char *value)
{
	if (sepgsqlIsEnabled())
		return sepgsqlGramSecurityItem(defname, value);
	return NULL;
}

bool pgaceIsGramSecurityItem(DefElem *defel)
{
	if (sepgsqlIsEnabled())
		return sepgsqlIsGramSecurityItem(defel);
	return false;
}

void pgaceGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		return sepgsqlGramCreateRelation(rel, tuple, defel);
}

void pgaceGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		return sepgsqlGramCreateAttribute(rel, tuple, defel);
}

void pgaceGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		return sepgsqlGramAlterRelation(rel, tuple, defel);
}

void pgaceGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		return sepgsqlGramAlterAttribute(rel, tuple, defel);
}

void pgaceGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		sepgsqlGramCreateDatabase(rel, tuple, defel);
}

void pgaceGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		sepgsqlGramAlterDatabase(rel, tuple, defel);
}

void pgaceGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		sepgsqlGramCreateFunction(rel, tuple, defel);
}

void pgaceGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
	if (sepgsqlIsEnabled())
		sepgsqlGramAlterFunction(rel, tuple, defel);
}

/******************************************************************
 * DATABASE related hooks
 ******************************************************************/
void pgaceSetDatabaseParam(const char *name, char *argstring)
{
	if (sepgsqlIsEnabled())
		sepgsqlSetDatabaseParam(name, argstring);
}

void pgaceGetDatabaseParam(const char *name)
{
	if (sepgsqlIsEnabled())
		sepgsqlGetDatabaseParam(name);
}

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/
void pgaceCallFunction(FmgrInfo *finfo)
{
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, false);
}

bool pgaceCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata)
{
	if (sepgsqlIsEnabled())
		return sepgsqlCallFunctionTrigger(finfo, tgdata);
	return true;
}

void pgaceCallFunctionFastPath(FmgrInfo *finfo)
{
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, true);
}

Datum pgacePreparePlanCheck(Relation rel)
{
	Oid saved = InvalidOid;

	if (sepgsqlIsEnabled())
		saved = sepgsqlPreparePlanCheck(rel);
	return ObjectIdGetDatum(saved);
}

void pgaceRestorePlanCheck(Relation rel, Datum pgace_saved)
{
	if (sepgsqlIsEnabled())
		sepgsqlRestorePlanCheck(rel, DatumGetObjectId(pgace_saved));
}

/******************************************************************
 * TABLE related hooks
 ******************************************************************/
void pgaceLockTable(Oid relid)
{
	if (sepgsqlIsEnabled())
		sepgsqlLockTable(relid);
}

/******************************************************************
 * COPY TO/COPY FROM statement hooks
 ******************************************************************/
void pgaceCopyTable(Relation rel, List *attNumList, bool isFrom) {
	if (sepgsqlIsEnabled())
		sepgsqlCopyTable(rel, attNumList, isFrom);
}

bool pgaceCopyToTuple(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlCopyToTuple(rel, tuple);
	return true;
}

/******************************************************************
 * Loadable shared library module hooks
 ******************************************************************/
void pgaceLoadSharedModule(const char *filename) {
	if (sepgsqlIsEnabled())
		sepgsqlLoadSharedModule(filename);
}

/******************************************************************
 * Binary Large Object (BLOB) hooks
 ******************************************************************/

Oid pgaceLargeObjectGetSecurity(HeapTuple tuple) {
	if (!sepgsqlIsEnabled())
		selerror("SELinux is disabled");
	return sepgsqlLargeObjectGetSecurity(tuple);
}

void pgaceLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectSetSecurity(tuple, lo_security, is_first);
}

void pgaceLargeObjectCreate(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectCreate(rel, tuple);
}

void pgaceLargeObjectDrop(Relation rel, HeapTuple tuple) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectDrop(rel, tuple);
}

void pgaceLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectOpen(rel, tuple, read_only);
}

void pgaceLargeObjectRead(Relation rel, HeapTuple tuple, bool is_first) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectRead(rel, tuple);
}

void pgaceLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup, bool is_first) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectWrite(rel, newtup, oldtup);
}

void pgaceLargeObjectTruncate(Relation rel, Oid loid) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectTruncate(rel, loid);
}

void pgaceLargeObjectImport(int fd) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectImport();
}

void pgaceLargeObjectExport(int fd, Oid loid) {
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectExport();
}

/******************************************************************
 * Security Label hooks
 ******************************************************************/
char *pgaceSecurityLabelIn(char *seclabel)
{
	if (sepgsqlIsEnabled())
		seclabel = sepgsqlSecurityLabelIn(seclabel);
	return seclabel;
}

char *pgaceSecurityLabelOut(char *seclabel)
{
	if (sepgsqlIsEnabled())
		seclabel = sepgsqlSecurityLabelOut(seclabel);
	return seclabel;
}

bool pgaceSecurityLabelIsValid(char *seclabel)
{
	if (sepgsqlIsEnabled())
		return sepgsqlSecurityLabelIsValid(seclabel);
	return true;
}

char *pgaceSecurityLabelOfLabel(char *new_label)
{
	if (sepgsqlIsEnabled())
		return sepgsqlSecurityLabelOfLabel(new_label);
	return pstrdup("unlabeled");
}

char *pgaceSecurityLabelNotFound(Oid sid)
{
	if (sepgsqlIsEnabled())
		return sepgsqlSecurityLabelNotFound(sid);
	return pstrdup("unlabeled");
}

/******************************************************************
 * Extended node type hooks
 ******************************************************************/
Node *pgaceCopyObject(Node *orig)
{
	if (sepgsqlIsEnabled())
		return sepgsqlCopyObject(orig);
	return NULL;
}

bool pgaceOutObject(StringInfo str, Node *node)
{
	if (sepgsqlIsEnabled())
		sepgsqlOutObject(str, node);
	return false;
}

void *pgaceReadObject(char *token)
{
	void *result = NULL;

	if (sepgsqlIsEnabled())
		result = sepgsqlReadObject(token);
	return NULL;
}
