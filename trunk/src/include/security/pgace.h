/*
 * include/security/pgace.h
 *   headers for PostgreSQL Access Control Extensions (PGACE)
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef PGACE_H
#define PGACE_H

#include "access/htup.h"
#include "commands/trigger.h"
#include "lib/stringinfo.h"
#include "nodes/execnodes.h"
#include "nodes/parsenodes.h"
#include "storage/itemptr.h"
#include "storage/large_object.h"
#include "tcop/dest.h"
#include "utils/rel.h"

/*
 * SECURITY_SYSATTR_NAME is the name of system column name
 * for security attribute, defined in pg_config.h
 * If it is not defined, security attribute support is disabled
 *
 * see, src/include/pg_config.h
 */

#ifdef HAVE_SELINUX
#include "security/sepgsql.h"
// the following line will be fixed by Sun's people
// #elifdef HAVE_SOLARISTX
// #include "security/solaristx.h"
#else

/******************************************************************
 * Initialize / Finalize related hooks
 ******************************************************************/

/*
 * pgaceShmemSize() have to return the size of shared memory segment
 * required by PGACE implementation. If no shared memory segment needed,
 * it should return 0.
 */
static inline Size pgaceShmemSize(void) {
	return 0;
}

/*
 * pgaceInitialize() is called when a new PostgreSQL instance is generated.
 * A PGACE implementation can initialize itself.
 */
static inline void pgaceInitialize(void) {
	/* do nothing */
}

/*
 * pgaceInitializePostmaster() is called when a postmaster server process
 * is started up. If it returns false, the server starting up process
 * will be aborted.
 */
static inline bool pgaceInitializePostmaster(void) {
	return true;
}

/*
 * pgaceFinalizePostmaster() is called when a postmaster server process
 * is just ending up.
 */
static inline void pgaceFinalizePostmaster(void) {
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
static inline List *pgaceProxyQuery(List *queryList) {
	return queryList;
}

/*
 * pgacePortalStart() is called on the top of PortalStart().
 *
 * @portal : a Portal object currently executed.
 */
static inline void pgacePortalStart(Portal portal) {
	/* do nothing */
}

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/

/*
 * pgaceExecInsert() is called when a client tries to insert a new tuple
 * via explicit INSERT statement from ExecInsert() at execMain.c
 * If it returns false, insertion of the tuple will be cancelled.
 *
 * @rel            : the target relation of INSERT
 * @tuple          : the contains of the inserted tuple
 * @with_returning : true, if the query has RETURNING clause
 */
static inline bool pgaceExecInsert(Relation rel, HeapTuple tuple, bool with_returning) {
	return true;
}

/*
 * pgaceExecUpdate() is called when clients tries to update a tuple
 * via explicit UPDATE statement from ExecUpdate() at execMain.c
 * If it returns false, updating the tuple will be cancelled.
 *
 * @rel            : the target relation of UPDATE
 * @newtup         : the new contains of the updated tuple
 * @tid            : ItemPointer of the tuple updated
 * @with_returning : true, if the query has RETURNING clause
 */
static inline bool pgaceExecUpdate(Relation rel, HeapTuple newtup, ItemPointer tid, bool with_returning) {
	return true;
}

/*
 * pgaceExecUpdate() is called when clients tries to delete a tuple
 * via explicit DELETE statement from ExecDelete() at execMain.c
 * If it returns false, deletion of the tuple will be cancelled.
 *
 * @rel            : the target relation of DELETE
 * @tid            : ItemPointer of the tuple deleted
 * @with_returning : true, if the query has RETURNING clause
 */
static inline bool pgaceExecDelete(Relation rel, ItemPointer tid, bool with_returning) {
	return true;
}

/*
 * pgaceSimpleHeapInsert() is called just before simple_heap_insert() is processed
 *
 * @rel   : the target relation of simple_heap_insert()
 * @tuple : the contains of the inserted tuple
 */
static inline void pgaceSimpleHeapInsert(Relation rel, HeapTuple tuple) {
	/* do nothing */
}

/*
 * pgaceSimpleHeapUpdate() is called just before simple_heap_update() is processed
 *
 * @rel   : the target relation of simple_heap_update()
 * @tid   : ItemPointer of the tuple updated
 * @tuple : the new contains of the updated tuple
 */
static inline void pgaceSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple tuple) {
	/* do nothing */
}

/*
 * pgaceSimpleHeapDelete() is called just before simple_heap_delete() is processed
 *
 * @rel : the target relation of simple_heap_delete()
 * @tid : ItemPointer of the tuple deleted
 */
static inline void pgaceSimpleHeapDelete(Relation rel, ItemPointer tid) {
	/* do nothing */
}

/*
 * pgaceHeapInsert() is called from heap_insert()
 *
 * @rel   : the target relation of heap_insert()
 * @tuple : the contains of the inserted tuples. It also contains system attribute like Oid
 */
static inline void pgaceHeapInsert(Relation rel, HeapTuple tuple) {
	/* do nothing */
}

/*
 * pgaceHeapUpdate() is called from heap_update()
 *
 * @rel    : the target relation of heap_update()
 * @newtup : the contains of the updated tuples. It also contains system attribute like Oid
 * @oldtup : the tuple which will be updated
 */
static inline void pgaceHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup) {
	/* do nothing */
}

/*
 * pgaceHeapDelete() is called from heap_delete()
 *
 * @rel    : the target relation of heap_delete()
 * @oldtup : the tuple which will be deleted
 */
static inline void pgaceHeapDelete(Relation rel, HeapTuple oldtup) {
	/* do nothing */
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
static inline DefElem *pgaceGramSecurityLabel(char *defname, char *value) {
	return NULL;
}

/*
 * PGACE implementation has to return true, if the given DefElem holds
 * security label generated in pgaceGramSecurityLabel(). false, if any other.
 *
 * @defel : given DefElem object
 */
static inline bool pgaceNodeIsSecurityLabel(DefElem *defel) {
	return false;
}

/*
 * pgaceCreateRelation() is called to create a new relation with explicitly specified
 * security attribute.
 *
 * @rel   : pg_class relation, opened with RowExclusiveLock
 * @tuple : the tuple for newly generated relation
 * @defel : DefElem object, if specified. (my be NULL)
 */
static inline void pgaceCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel) {
	/* do nothing */
}

/*
 * pgaceAlterRelation() is called to modify security attribute of the relation.
 *
 * @rel   : pg_class relation, opened with RowExclusiveLock
 * @tuple : the target tuple to be set security attribute
 * @defel : DefElem object to represent security attribute.
 */
static inline void pgaceAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel) {
	/* do nothing */
}

/*
 * pgaceCreateAttribute() is called to create a new column with explicitly specified
 * security attribute.
 *
 * @rel   : pg_attribute relation, opened with RowExclusiveLock
 * @tuple : the tuple for newly generated column
 * @defel : DefElem object, if specified. (my be NULL)
 */
static inline void pgaceCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel) {
	/* do nothing */
}

/*
 * pgaceAlterAttribute() is called to modify security attribute of the attribute.
 *
 * @rel   : pg_attribute relation, opened with RowExclusiveLock
 * @tuple : the target tuple to be set security attribute
 * @defel : DefElem object to represent security attribute.
 */
static inline void pgaceAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel) {
	/* do nothing */
}

/*
 * pgaceCreateDatabase() is called to create a new database with explicit specified
 * security attribute.
 *
 * @rel        : pg_database relation, opened with RowExclusiveLock
 * @tuple      : the tuple for newly generated database
 * @pgace_elem : DefElem object, if specified. (may be NULL)
 */
static inline void pgaceCreateDatabase(Relation rel, HeapTuple tuple, DefElem *pgace_elem) {
	/* do nothing */
}

/*
 * pgaceAlterDatabase() is called to modify the database meta-information alterd just
 * before updating the HeapTuple associated.
 *
 * @rel        : pg_database relation, opened with RowExclusiveLock
 * @tuple      : new meta information of the target database
 * @pgace_elem : DefElem object generated in pgaceGramAlterDatabase()
 */
static inline void pgaceAlterDatabase(Relation rel, HeapTuple tuple, DefElem *pgace_elem) {
	/* do nothing */
}

/*
 * pgaceCreateFunction() is called to create a new function with explicit specified
 * security attribute.
 *
 * @rel        : pg_proc relation, opened with RowExclusiveLock
 * @tuple      : the tuple for newly generated function
 * @pgace_attr : security label, if specified. (may be NULL)
 */
static inline void pgaceCreateFunction(Relation rel, HeapTuple tuple, DefElem *pgace_elem) {
	/* do nothing */
}

/*
 * pgaceAlterFunction() is called to modify the function meta-information alterd just
 * before updating the HeapTuple associated.
 *
 * @rel        : pg_proc relation, opened with RowExclusiveLock
 * @tuple      : new meta information of the target function
 * @pgace_elem : DefElem object generated in pgaceGramAlterFunction()
 */
static inline void pgaceAlterFunction(Relation rel, HeapTuple tuple, DefElem *pgace_elem) {
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
static inline void pgaceSetDatabaseParam(const char *name, char *argstring) {
	/* do nothing */
}

/*
 * pgaceGetDatabaseParam() is called when clients tries to refer GUC variables
 *
 * @name : The name of GUC variable
 */
static inline void pgaceGetDatabaseParam(const char *name) {
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
static inline void pgaceCallFunction(FmgrInfo *finfo) {
	/* do nothing */
}

/*
 * pgaceCallFunctionTrigger() is called just before executing
 * trigger function.
 *
 * @finfo  : FmgrInfo object for the target function
 * @tgdata : TriggerData object for the current trigger invokation
 */
static inline void pgaceCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata) {
	/* do nothing */
}

/*
 * pgaceCallFunctionFastPath() is called just before executing
 * SQL function in the fast path.
 *
 * @finfo  : FmgrInfo object for the target function
 */
static inline void pgaceCallFunctionFastPath(FmgrInfo *finfo) {
	/* do nothing */
}

/*
 * pgacePreparePlanCheck() is called before foreign key/primary key constraint checks,
 * at ri_PlanCheck(). PGACE implementation can return its opaque data for any purpose.
 *
 * @rel : the target relation in which a constraint is configured
 */
static inline Datum pgacePreparePlanCheck(Relation rel) {
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
static inline void pgaceRestorePlanCheck(Relation rel, Datum pgace_saved) {
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
static inline void pgaceLockTable(Oid relid) {
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
static inline bool pgaceAlterTable(Relation rel, AlterTableCmd *cmd) {
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
static inline void pgaceCopyTable(Relation rel, List *attNumList, bool isFrom) {
	/* do nothing */
}

/*
 * pgaceCopyTuple() is called to check whether the given tuple should be
 * filtered, or not in the process of COPY TO statement.
 * If it returns false, the given tuple will be filtered from the result set
 *
 * @rel   : the target relation
 * @tuple : the target tuple
 */
static inline bool pgaceCopyTuple(Relation rel, HeapTuple tuple) {
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
static inline void pgaceLoadSharedModule(const char *filename) {
	/* do nothing */
}

/******************************************************************
 * Binary Large Object (BLOB) hooks
 ******************************************************************/

/*
 * pgaceLargeObjectGetSecurity() is called when lo_get_security() is executed
 * It returns it's security attribute.
 *
 * @tuple : a tuple which is a part of the target largeobject.
 */
static inline Oid pgaceLargeObjectGetSecurity(HeapTuple tuple) {
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
static inline void pgaceLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first) {
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
static inline void pgaceLargeObjectCreate(Relation rel, HeapTuple tuple) {
	/* do nothing */
}

/*
 * pgaceLargeObjectDrop() is called when a large object is dropped once for
 * a large object
 *
 * @rel   : pg_largeobject relation opened with RowExclusiveLock
 * @tuple : one of the tuples within the target large object
 */
static inline void pgaceLargeObjectDrop(Relation rel, HeapTuple tuple) {
	/* do nothing */
}

/*
 * pgaceLargeObjectOpen() is called when a large object is opened
 *
 * @rel       : pg_largeobject relation opened with RowExclusiveLock
 * @tuple     : head of the tuples within the target large object
 * @read_only : true, if large object is opened as read only mode
 */
static inline void pgaceLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only) {
	/* do nothing */
}

/*
 * pgaceLargeObjectRead is called when they read from a large object
 *
 * @rel   : pg_largeobject relation opened with AccessShareLock
 * @tuple : a tuple within the target large object
 */
static inline void pgaceLargeObjectRead(Relation rel, HeapTuple tuple) {
	/* do nothing */
}

/*
 * pgaceLargeObjectWrite() is called when they write to a large object
 *
 * @rel    : pg_largeobject relation opened with RowExclusiveLock
 * @newtup : a new tuple within the target large object
 * @oldtup : a original tuple within the target large object, if exist
 */
static inline void pgaceLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup) {
	/* do nothing */
}

/*
 * pgaceLargeObjectImport() is called when lo_import() is processed
 */
static inline void pgaceLargeObjectImport(void) {
	/* do nothing */
}

/*
 * pgaceLargeObjectExport() is called when lo_import() is processed
 */
static inline void pgaceLargeObjectExport(void) {
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
static inline char *pgaceSecurityLabelIn(char *seclabel) {
	return seclabel;
}

/*
 * PGACE implementation can use pgaceSecurityLabelOut() hook to translate
 * a security label in internal representation into external one.
 * If no translation is necessary, it has to return @seclabel as is.
 *
 * @seclabel : security label being output
 */
static inline char *pgaceSecurityLabelOut(char *seclabel) {
	return seclabel;
}

/*
 * pgaceSecurityLabelIsValid() checks whether the @seclabel is valid or not.
 * return false, if @seclabel is not valid security attribute in text representation.
 *
 * @seclabel : security attribute in text representation
 */
static inline bool pgaceSecurityLabelIsValid(char *seclabel) {
	return true;
}

/*
 * pgaceSecurityLabelOfLabel() returns the security attribute of a newly
 * generated tuple within pg_security
 *
 * @new_label : a text representation of security context which will be newly
 *              inserted into pg_security.
 */
static inline char *pgaceSecurityLabelOfLabel(char *new_label) {
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
static inline Node *pgaceCopyObject(Node *orig) {
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
static inline bool pgaceOutObject(StringInfo str, Node *node) {
	return false;
}

#endif

/* writable system column support */
#ifdef SECURITY_SYSATTR_NAME
static inline bool pgaceWritableSystemColumn(int attrno) {
	return ((attrno == SecurityAttributeNumber) ? true : false);
}
extern void pgaceTransformSelectStmt(List *targetList);
extern void pgaceTransformInsertStmt(List **p_icolumns, List **p_attrnos, List *targetList);
extern void pgaceFetchSecurityLabel(JunkFilter *junkfilter, TupleTableSlot *slot, Oid *tts_security);
#else
static inline bool pgaceWritableSystemColumn(int attrno) {
	return false;
}
static inline void pgaceTransformSelectStmt(List *targetList) { /* do nothing */ }
static inline void pgaceTransformInsertStmt(List **p_icolumns,
											List **p_attrnos,
											List *targetList) { /* do nothing */ }
static inline void pgaceFetchSecurityLabel(JunkFilter *junkfilter,
										   TupleTableSlot *slot,
										   Oid *tts_security) { /* do nothing */ }
#endif

/* Extended SQL statements related */
extern List *pgaceBuildAttrListForRelation(CreateStmt *stmt);
extern void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list);
extern void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list);
extern void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd);

/* SQL functions related to security label */
extern Datum security_label_in(PG_FUNCTION_ARGS);
extern Datum security_label_out(PG_FUNCTION_ARGS);
extern Datum security_label_raw_in(PG_FUNCTION_ARGS);
extern Datum security_label_raw_out(PG_FUNCTION_ARGS);
extern Datum text_to_security_label(PG_FUNCTION_ARGS);
extern Datum security_label_to_text(PG_FUNCTION_ARGS);

/* SQL functions related to large object */
extern Datum lo_get_security(PG_FUNCTION_ARGS);
extern Datum lo_set_security(PG_FUNCTION_ARGS);

#endif // PGACE_H
