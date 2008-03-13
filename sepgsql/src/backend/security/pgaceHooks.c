/*
 * src/backend/security/pgaceHooks.c
 *   Dummy functions of PostgreSQL Access Control Extension
 *   when no users enables the framework.
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "security/pgace.h"

#ifdef HAVE_SELINUX
#include "executor/executor.h"
#include "security/pgace.h"
#include "security/sepgsql.h"
#endif /* HAVE_SELINUX */

/******************************************************************
 * Initialize / Finalize related hooks
 ******************************************************************/

/*
 * pgaceShmemSize() have to return the size of shared memory segment
 * required by PGACE implementation. If no shared memory segment needed,
 * it should return 0.
 */
Size pgaceShmemSize(void)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlShmemSize();
#endif
	return (Size) 0;
}

/*
 * pgaceInitialize() is called when a new PostgreSQL instance is generated.
 * A PGACE implementation can initialize itself.
 *
 * @is_bootstrap : true, if bootstraping mode.
 */
void pgaceInitialize(bool is_bootstrap)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlInitialize(is_bootstrap);
#endif
	/* do nothing */
}

/*
 * pgaceInitializePostmaster() is called when a postmaster server process
 * is started up. If it returns false, the server starting up process
 * will be aborted.
 */
bool pgaceInitializePostmaster(void)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlInitializePostmaster();
#endif
	return true;
}

/*
 * pgaceFinalizePostmaster() is called when a postmaster server process
 * is just ending up.
 */
void pgaceFinalizePostmaster(void)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlFinalizePostmaster();
#endif
	/* do nothing */
}

/******************************************************************
 * SQL proxy hooks
 ******************************************************************/

/*
 * pgaceProxyQuery() is called just after query rewrite phase.
 * PGACE implementation can modify the query trees in this hook,
 * if necessary.
 *
 * @queryList : a list of Query typed objects.
 */
List *pgaceProxyQuery(List *queryList)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled()) {
		List *newList = NIL;
		ListCell *l;

		foreach (l, queryList) {
			Query *q = (Query *) lfirst(l);

			newList = list_concat(newList, sepgsqlProxyQuery(q));
		}
		queryList = newList;
	}
#endif
	return queryList;
}

/*
 * pgacePortalStart() is called on the top of PortalStart().
 *
 * @portal : a Portal object currently executed.
 */
void pgacePortalStart(Portal portal)
{
	/* do nothing */
}

/*
 * pgaceExecutorStart() is called on the top of ExecutorStart().
 *
 * @queryDesc : a QueryDesc object given to ExecutorStart().
 * @eflags    : eflags valus given to ExecutorStart().
 *              if EXEC_FLAG_EXPLAIN_ONLY is set, no real access will run.
 */
void pgaceExecutorStart(QueryDesc *queryDesc, int eflags)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled() && !(eflags & EXEC_FLAG_EXPLAIN_ONLY)) {
		Assert(queryDesc->plannedstmt != NULL);
		sepgsqlVerifyQuery(queryDesc->plannedstmt);
	}
#endif
	/* do nothing */
}

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/

/*
 * pgaceHeapTupleInsert() is called when a new tuple attempt to be inserted.
 * If it returns false, this insertion of a new tuple will be cancelled.
 * However, it does not generate any error.
 *
 * @rel            : the target relation
 * @tuple          : the tuple attmpt to be inserted
 * @is_internal    : true, if this operation is invoked by system internal processes.
 * @with_returning : true, if INSERT statement has RETURNING clause.
 */
bool pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
						  bool is_internal, bool with_returning)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleInsert(rel, tuple, is_internal, with_returning);
#endif
	return true;
}

/*
 * pgaceHeapTupleUpdate() is called when a tuple attempt to be updated.
 * If it returns false, this update will be cancelled.
 * However, it does not generate any error.
 *
 * @rel            : the target relation
 * @otid           : ItemPointer of the tuple to be updated
 * @newtup         : the new contains of the updated tuple
 * @is_internal    : true, if this operation is invoked by system internal processes.
 * @with_returning : true, if INSERT statement has RETURNING clause.
 */
bool pgaceHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
						  bool is_internal, bool with_returning)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleUpdate(rel, otid, newtup, is_internal, with_returning);
#endif
	return true;
}

/*
 * pgaceHeapTupleDelete() is called when a tuple attempt to be deleted.
 * If it returns false, this deletion will be cancelled.
 * However, it does not generate any error.
 *
 * @rel            : the target relation
 * @otid           : ItemPointer of the tuple to be deleted
 * @is_internal    : true, if this operation is invoked by system internal processes.
 * @with_returning : true, if INSERT statement has RETURNING clause.
 */
bool pgaceHeapTupleDelete(Relation rel, ItemPointer otid,
						  bool is_internal, bool with_returning)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleDelete(rel, otid, is_internal, with_returning);
#endif
	return true;
}

/******************************************************************
 * Extended SQL statement hooks
 ******************************************************************/
/*
 * PGACE implementation can use pgaceGramSecurityItem() hook to extend
 * SQL statement for security purpose. This hook is deployed on parser/gram.y
 * as a part of the SQL grammer. If no SQL extension is necessary, it has to
 * return NULL to cause yyerror().
 *
 * @defname : given <parameter> string
 * @value   : given <value> string
 */
DefElem *pgaceGramSecurityItem(char *defname, char *value)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramSecurityItem(defname, value);
#endif
	return NULL;
}

/*
 * PGACE implementation has to return true, if the given DefElem holds
 * security item generated in pgaceGramSecurityItem(). false, if any other.
 *
 * @defel : given DefElem object
 */
bool pgaceIsGramSecurityItem(DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlIsGramSecurityItem(defel);
#endif
	return false;
}

/*
 * pgaceGramCreateRelation() is called to modify a tuple just before inserting
 * a new relation with CREATE TABLE, if extended statement is used.
 *
 * @rel   : pg_class relation
 * @tuple : a tuple of new relation
 * @defel : extended statement
 */
void pgaceGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramCreateRelation(rel, tuple, defel);
#endif
	/* do nothing */
}

/*
 * pgaceGramCreateAttribute() is called to modify a tuple just before inserting
 * a new attribute with CREATE TABLE, if extended statement is used.
 *
 * @rel   : pg_attribute relation
 * @tuple : a tuple of new attribute
 * @defel : extended statement
 */
void pgaceGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramCreateAttribute(rel, tuple, defel);
#endif
	/* do nothing */
}

/*
 * pgaceGramAlterRelation() is called to modify a tuple just before updating
 * a relation with ALTER TABLE, if extended statement is used.
 *
 * @rel   : target relation
 * @tuple : a tuple of new relation
 * @defel : extended statement
 */
void pgaceGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramAlterRelation(rel, tuple, defel);
#endif
	/* do nothing */
}

/*
 * pgaceGramAlterAttribute() is called to modify a tuple just before updating
 * an attribute with ALTER TABLE, if extended statement is specified.
 *
 * @rel   : target relation
 * @tuple : a tuple of new attribute
 * @defel : extended statement
 */
void pgaceGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramAlterAttribute(rel, tuple, defel);
#endif
	/* do nothing */
}

/*
 * pgaceGramCreateDatabase() is called to modify a tuple just before inserting
 * a new database with CREATE DATABASE, if extended statement is used.
 *
 * @rel   : pg_database relation
 * @tuple : a tuple of the new database
 * @defel : extended statement
 */
void pgaceGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramCreateDatabase(rel, tuple, defel);
#endif
	/* do nothing */
}

/*
 * pgaceGramAlterDatabase() is called to modify a tuple just before updating
 * a database with ALTER DATABASE, if extended statement is used.
 *
 * @rel   : pg_database relation
 * @tuple : a tuple of the updated database
 * @defel : extended statement
 */
void pgaceGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramAlterDatabase(rel, tuple, defel);
#endif
	/* do nothing */
}

/*
 * pgaceGramCreateFunction() is called to modify a tuple just before inserting
 * a new function into pg_proc, if extended statement is used.
 *
 * @rel   : pg_proc relation
 * @tuple : a tuple of the new function
 * @defel : extended statement
 */
void pgaceGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramCreateFunction(rel, tuple, defel);
#endif
	/* do nothing */
}

/*
 * pgaceGramAlterFunction() is called to modify a tuple just before updating
 * a function with ALTER FUNCTION, if extended statement is used.
 *
 * @rel   : pg_proc relation
 * @tuple : a tuple of the function
 * @defel : extended statement
 */
void pgaceGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramAlterFunction(rel, tuple, defel);
#endif
	/* do nothing */
}

/******************************************************************
 * DATABASE related hooks
 ******************************************************************/

/*
 * pgaceSetDatabaseParam() is called when clients tries to set GUC variables
 *
 * @name   : The name of GUC variable
 * @argstr : The new valus of GUC variable. If argstr is NULL, it means
 *           clients tries to reset the variable.
 */
void pgaceSetDatabaseParam(const char *name, char *argstring)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlSetDatabaseParam(name, argstring);
#endif
	/* do nothing */
}

/*
 * pgaceGetDatabaseParam() is called when clients tries to refer GUC variables
 *
 * @name : The name of GUC variable
 */
void pgaceGetDatabaseParam(const char *name)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGetDatabaseParam(name);
#endif
	/* do nothing */
}

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/

/*
 * pgaceCallFunction() is called just before executing SQL function
 * as a part of query.
 *
 * @finfo    : FmgrInfo object for the target function
 */
void pgaceCallFunction(FmgrInfo *finfo)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, false);
#endif
	/* do nothing */
}

/*
 * pgaceCallFunctionTrigger() is called just before executing
 * trigger function. 
 * If it returns false, the trigger function will not be called and caller
 * receives NULL tuple as a result. In the case when Before-Row triggers,
 * it means the current operations on the tuple should be skipped.
 *
 * @finfo  : FmgrInfo object for the target function
 * @tgdata : TriggerData object for the current trigger invokation
 */
bool pgaceCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlCallFunctionTrigger(finfo, tgdata);
#endif
	return true;
}

/*
 * pgaceCallFunctionFastPath() is called just before executing
 * SQL function in the fast path.
 *
 * @finfo  : FmgrInfo object for the target function
 */
void pgaceCallFunctionFastPath(FmgrInfo *finfo)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, true);
#endif
	/* do nothing */
}

/*
 * pgacePreparePlanCheck() is called before foreign key/primary key constraint checks,
 * at ri_PlanCheck(). PGACE implementation can return its opaque data for any purpose.
 *
 * @rel : the target relation in which a constraint is configured
 */
Datum pgacePreparePlanCheck(Relation rel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled()) {
		Oid saved;

		saved = sepgsqlPreparePlanCheck(rel);
		return ObjectIdGetDatum(saved);
	}
#endif
	return (Datum) 0;
}

/*
 * pgaceRestorePlanCheck() is called after foreign key/primary key constraint checks,
 * at ri_PlanCheck(). PGACE implementation can use an opaque data generated in the above
 * pgacePreparePlanCheck().
 *
 * @rel         : the target relation in which a constraint is configured
 * @pgace_saved : an opaque data returned from pgacePreparePlanCheck()
 */
void pgaceRestorePlanCheck(Relation rel, Datum pgace_saved)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlRestorePlanCheck(rel, DatumGetObjectId(pgace_saved));
#endif
	/* do nothing */
}

/******************************************************************
 * TABLE related hooks
 ******************************************************************/

/*
 * pgaceLockTable() is called when explicit LOCK statement used.
 *
 * @relid : the target relation id
 */
void pgaceLockTable(Oid relid)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLockTable(relid);
#endif
	/* do nothing */
}

/******************************************************************
 * COPY TO/COPY FROM statement hooks
 ******************************************************************/

/*
 * pgaceCopyTable() is called when COPY TO/COPY FROM statement is processed
 *
 * @rel        : the target relation
 * @attNumList : the list of attribute numbers
 * @isFrom     : true, if the given statement is 'COPY FROM'
 */
void pgaceCopyTable(Relation rel, List *attNumList, bool isFrom) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlCopyTable(rel, attNumList, isFrom);
#endif
	/* do nothing */
}

/*
 * pgaceCopyToTuple() is called to check whether the given tuple should be
 * filtered, or not in the process of COPY TO statement.
 * If it returns false, the given tuple will be filtered from the result set
 *
 * @rel        : the target relation
 * @attNumList : the list of attribute numbers
 * @tuple      : the target tuple
 */
bool pgaceCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlCopyToTuple(rel, attNumList, tuple);
#endif
	return true;
}

/******************************************************************
 * Loadable shared library module hooks
 ******************************************************************/

/*
 * pgaceLoadSharedModule() is called just before load a shared library
 * module.
 *
 * @filename : full path name of the shared library module
 */
void pgaceLoadSharedModule(const char *filename) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLoadSharedModule(filename);
#endif
	/* do nothing */
}

/******************************************************************
 * Binary Large Object (BLOB) hooks
 ******************************************************************/

/*
 * pgaceLargeObjectGetSecurity() is called when lo_get_security() is executed
 * It returns its security attribute.
 *
 * @tuple : a tuple which is a part of the target largeobject.
 */
void pgaceLargeObjectGetSecurity(HeapTuple tuple) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectGetSecurity(tuple);
#else
	elog(ERROR, "PGACE: There is no guest module.");
#endif
}

/*
 * pgaceLargeObjectSetSecurity() is called when lo_set_security() is executed
 *
 * @tuple       : a tuple which is a part of the target largeobject.
 * @lo_security : new security attribute specified
 */
void pgaceLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectSetSecurity(tuple, lo_security);
#else
	elog(ERROR, "PGACE: There is no guest module.");
#endif
}

/*
 * pgaceLargeObjectCreate() is called when a new large object is created
 *
 * @rel   : pg_largeobject relation opened with RowExclusiveLock
 * @tuple : a new tuple for the new large object
 */
void pgaceLargeObjectCreate(Relation rel, HeapTuple tuple) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectCreate(rel, tuple);
#endif
	/* do nothing */
}

/*
 * pgaceLargeObjectDrop() is called when a large object is dropped once for
 * a large object
 *
 * @rel   : pg_largeobject relation opened with RowExclusiveLock
 * @tuple : one of the tuples within the target large object
 */
void pgaceLargeObjectDrop(Relation rel, HeapTuple tuple) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectDrop(rel, tuple);
#endif
	/* do nothing */
}

/*
 * pgaceLargeObjectRead is called when they read from a large object
 *
 * @rel   : pg_largeobject relation opened with AccessShareLock
 * @tuple : the head tuple within the given large object
 */
void pgaceLargeObjectRead(Relation rel, HeapTuple tuple) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectRead(rel, tuple);
#endif
	/* do nothing */
}

/*
 * pgaceLargeObjectWrite() is called when they write to a large object
 *
 * @rel    : pg_largeobject relation opened with RowExclusiveLock
 * @newtup : the head tuple within the given large object
 * @oldtup : the head tuple in older version, if exist
 */
void pgaceLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectWrite(rel, newtup, oldtup);
#endif
	/* do nothing */
}

/*
 * pgaceLargeObjectTruncate() is called when they truncate a large object.
 *
 * @rel     : pg_largeobject relation opened with RowExclusiveLock
 * @loid    : large object identifier
 * @headtup : the head tuple to be truncated. NULL means this BLOB will be expanded.
 */
void pgaceLargeObjectTruncate(Relation rel, Oid loid, HeapTuple headtup) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectTruncate(rel, loid, headtup);
#endif
	/* do nothing */
}

/*
 * pgaceLargeObjectImport() is called when lo_import() is processed
 *
 * @fd : file descriptor to be inported
 */
void pgaceLargeObjectImport(int fd) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectImport();
#endif
	/* do nothing */
}

/*
 * pgaceLargeObjectExport() is called when lo_import() is processed
 *
 * @fd   : file descriptor to be exported
 * @loid : large object to be exported
 */
void pgaceLargeObjectExport(int fd, Oid loid) {
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectExport();
#endif
	/* do nothing */
}

/******************************************************************
 * Security Label hooks
 ******************************************************************/

/*
 * PGACE implementation can use pgaceSecurityLabelIn() hook to translate
 * a input security label from external representation into internal one.
 * If no translation is necessary, it has to return @seclabel as is.
 *
 * @seclabel : security label being input
 */
char *pgaceSecurityLabelIn(char *seclabel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		seclabel = sepgsqlSecurityLabelIn(seclabel);
#endif
	return seclabel;
}

/*
 * PGACE implementation can use pgaceSecurityLabelOut() hook to translate
 * a security label in internal representation into external one.
 * If no translation is necessary, it has to return @seclabel as is.
 *
 * @seclabel : security label being output
 */
char *pgaceSecurityLabelOut(char *seclabel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		seclabel = sepgsqlSecurityLabelOut(seclabel);
#endif
	return seclabel;
}

/*
 * pgaceSecurityLabelCheckValid() checks whether the @seclabel is valid or not.
 * In addition, it can returns an alternative security label, if possible.
 * 
 * It has to return @seclabel as is, if @seclabel is a valid security label.
 * It can return an alternative label, if @seclabel is NOT a valid one and
 * there is an alternative. In any other case, it returns NULL.
 * @seclabel may be NULL. In this case, @seclabel is always invalid.
 *
 * @seclabel : security label to be checked
 */
char *pgaceSecurityLabelCheckValid(char *seclabel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlSecurityLabelCheckValid(seclabel);
#endif
	return seclabel;
}

/*
 * pgaceSecurityLabelOfLabel() returns the security attribute of a newly
 * generated tuple within pg_security
 *
 * @new_label : a text representation of security context which will be newly
 *              inserted into pg_security.
 */
char *pgaceSecurityLabelOfLabel(char *new_label)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlSecurityLabelOfLabel(new_label);
#endif
	return pstrdup("unlabeled");
}

/******************************************************************
 * Extended node type hooks
 ******************************************************************/

/*
 * If PGACE implementation requires new node type, a method to copy object.
 * pgaceCopyObject() provides a hook to copy new node typed object.
 * If a given object (@orig) has a tag extended by PGACE implementation,
 * it have to copy and return it.
 * If it returns NULL, @orig is not available for the PGACE implementation.
 *
 * @orig : a object which to copy
 */
Node *pgaceCopyObject(Node *orig)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlCopyObject(orig);
#endif
	return NULL;
}

/*
 * pgaceOutObject() provides a hook to translate a object to text representation.
 * If a given object (@node) has a tag extended by PGACE implementation, it have
 * to put a text representation into StringInfo.
 * If it returns false, @node is not available for the PGACE implementation.
 *
 * @str  : StringInfo which to put the text representation
 * @node : a object that text representation is required
 */
bool pgaceOutObject(StringInfo str, Node *node)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlOutObject(str, node);
#endif
	return false;
}

/*
 * pgaceReadObject() provides a hook to read a text representation of an object.
 * If a given token is a tag extended by PGACE implementation, it have to create
 * an object same as original one.
 *
 * @token : a tag for the object
 */
void *pgaceReadObject(char *token)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlReadObject(token);
#endif
	return NULL;
}

/******************************************************************
 * Extended functions stub
 ******************************************************************/

/*
 * In this section, you can put function stubs when your security
 * module is not activated.
 */
#ifndef HAVE_SELINUX
/*
 * SE-PostgreSQL adds three functions.
 * When it is disabled, call them causes an error.
 */
Datum sepgsql_getcon(PG_FUNCTION_ARGS)
{
	elog(ERROR, "%s is not implemented", __FUNCTION__);
	PG_RETURN_VOID();
}

Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS)
{
	elog(ERROR, "%s is not implemented", __FUNCTION__);
	PG_RETURN_VOID();
}

Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS)
{
	elog(ERROR, "%s is not implemented", __FUNCTION__);
	PG_RETURN_VOID();
}
#endif  /* HAVE_SELINUX */
