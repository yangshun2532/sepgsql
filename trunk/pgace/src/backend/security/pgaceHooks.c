/*
 * src/backend/security/pgaceHooks.c
 *   Dummy functions of PostgreSQL Access Control Extension
 *   when no users enables the framework.
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "security/pgace.h"

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
	/* do nothing */
}

/*
 * pgaceInitializePostmaster() is called when a postmaster server process
 * is started up. If it returns false, the server starting up process
 * will be aborted.
 */
bool pgaceInitializePostmaster(void)
{
	return true;
}

/*
 * pgaceFinalizePostmaster() is called when a postmaster server process
 * is just ending up.
 */
void pgaceFinalizePostmaster(void)
{
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
	return true;
}

/******************************************************************
 * Extended SQL statement hooks
 ******************************************************************/
/*
 * PGACE implementation can use pgaceGramSecurityLabel() hook to extend
 * SQL statement for explicit labeling. This hook is deployed on parser/gram.y
 * as a part of the SQL grammer. If no SQL extension is necessary, it has to
 * return NULL to cause yyerror().
 *
 * @defname : given <parameter> string
 * @value   : given <value> string
 */
DefElem *pgaceGramSecurityLabel(char *defname, char *value)
{
	return NULL;
}

/*
 * PGACE implementation has to return true, if the given DefElem holds
 * security label generated in pgaceGramSecurityLabel(). false, if any other.
 *
 * @defel : given DefElem object
 */
bool pgaceNodeIsSecurityLabel(DefElem *defel)
{
	return false;
}

/*
 * PGACE implementation has to translate DefElem object generated by 
 * pgaceGramSecurityLabel(), into t_security of HeapTupleHeader.
 *
 * @defel : given DefElem object
 */
Oid pgaceParseSecurityLabel(DefElem *defel)
{
	return InvalidOid;
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
 *
 * NOTE: In this hooks, implementation cannot cause an error.
 *       We have to generate an audit message and return false.
 */
bool pgaceSetDatabaseParam(const char *name, char *argstring)
{
	/* do nothing */
	return true;
}

/*
 * pgaceGetDatabaseParam() is called when clients tries to refer GUC variables
 *
 * @name : The name of GUC variable
 */
void pgaceGetDatabaseParam(const char *name)
{
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
	/* do nothing */
}

/*
 * pgaceAlterTable() is called to modify table/column. The PGACE implementation
 * have to update the target tuples within pg_class or pg_attribute.
 * If AlterTableCmd tag is unexpected one, 
 *
 * @rel : the target relation
 * @cmd : AlterTableCmd object
 */
bool pgaceAlterTable(Relation rel, AlterTableCmd *cmd)
{
	return false;
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
	/* do nothing */
}

/*
 * pgaceCopyToTuple() is called to check whether the given tuple should be
 * filtered, or not in the process of COPY TO statement.
 * If it returns false, the given tuple will be filtered from the result set
 *
 * @rel   : the target relation
 * @tuple : the target tuple
 */
bool pgaceCopyToTuple(Relation rel, HeapTuple tuple) {
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
Oid pgaceLargeObjectGetSecurity(HeapTuple tuple) {
	ereport(ERROR,
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("There is no security attribute support.")));
	return InvalidOid;
}

/*
 * pgaceLargeObjectSetSecurity() is called when lo_set_security() is executed
 *
 * @tuple       : a tuple which is a part of the target largeobject.
 * @lo_security : new security attribute specified
 * @is_first    : true, if it's the first call in the largeobject.
 *                Because a largeobject may contain some tuples, this hook
 *                may be called several times for a single largeobject.
 */
void pgaceLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first) {
	ereport(ERROR,
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("There is no security attribute support.")));
}

/*
 * pgaceLargeObjectCreate() is called when a new large object is created
 *
 * @rel   : pg_largeobject relation opened with RowExclusiveLock
 * @tuple : a new tuple for the new large object
 */
void pgaceLargeObjectCreate(Relation rel, HeapTuple tuple) {
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
	/* do nothing */
}

/*
 * pgaceLargeObjectOpen() is called when a large object is opened
 *
 * @rel       : pg_largeobject relation opened with RowExclusiveLock
 * @tuple     : head of the tuples within the target large object
 * @read_only : true, if large object is opened as read only mode
 */
void pgaceLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only) {
	/* do nothing */
}

/*
 * pgaceLargeObjectRead is called when they read from a large object
 *
 * @rel   : pg_largeobject relation opened with AccessShareLock
 * @tuple : a tuple within the target large object
 */
void pgaceLargeObjectRead(Relation rel, HeapTuple tuple) {
	/* do nothing */
}

/*
 * pgaceLargeObjectWrite() is called when they write to a large object
 *
 * @rel    : pg_largeobject relation opened with RowExclusiveLock
 * @newtup : a new tuple within the target large object
 * @oldtup : a original tuple within the target large object, if exist
 */
void pgaceLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup) {
	/* do nothing */
}

/*
 * pgaceLargeObjectImport() is called when lo_import() is processed
 */
void pgaceLargeObjectImport(void) {
	/* do nothing */
}

/*
 * pgaceLargeObjectExport() is called when lo_import() is processed
 */
void pgaceLargeObjectExport(void) {
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
	return seclabel;
}

/*
 * pgaceSecurityLabelIsValid() checks whether the @seclabel is valid or not.
 * return false, if @seclabel is not valid security attribute in text representation.
 *
 * @seclabel : security attribute in text representation
 */
bool pgaceSecurityLabelIsValid(char *seclabel)
{
	return true;
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
	return pstrdup("unlabeled");
}

/*
 * pgaceSecurityLabelNotFound() has to return a string representation of security
 * attribute, when no tuple with oid equals to @sid is within pg_security system
 * catalog.
 *
 * @sid : required sid, but not found on pg_security
 */
char *pgaceSecurityLabelNotFound(Oid sid)
{
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
	return false;
}




