/*
 * include/security/pgace.h
 *   headers for PostgreSQL Access Control Extensions (PGACE)
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "access/htup.h"
#include "lib/stringinfo.h"
#include "nodes/parsenodes.h"
#include "storage/itemptr.h"
#include "storage/large_object.h"
#include "tcop/dest.h"
#include "utils/rel.h"

#ifdef HAVE_SELINUX
#include "security/sepgsql.h"
// the following line will be fixed by Sun's people
// #elif HAVE_TRUSTED_SOLARIS
// #include "security/trusted_solaris.h"
#else
/*
 * SECURITY_SYSATTR_NAME is the definition of system column name for
 * security attribute. Clients can refer a security attribute via
 * this column which is defined as security_label type.
 */
#define SECURITY_SYSATTR_NAME		"__system_security_attribute__"

/******************************************************************
 * Initialize / Finalize related hooks
 ******************************************************************/

/*
 * pgaceShmemSize() have to returd the size of shared memory segment
 * required by PgACE implementation. If no shared memory segment needed,
 * it should return 0.
 */
static inline Size pgaceShmemSize(void) {
	return 0;
}

/*
 * pgaceInitialize() is called when a new PostgreSQL instance is generated.
 * A PgACE implementation can initialize itself.
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
 * PgACE implementation can modify the query trees in this hook,
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
 * pgaceExecInsert() is called when clients tries to insert a new tuple
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
 * @name : The name of GUN variable
 */
static inline void pgaceGetDatabaseParam(const char *name) {
	/* do nothing */
}

/*
 * pgaceGramAlterDatabase() is called when yacc/lex engine detect the following statement:
 *     ALTER DATABASE <database name> <parameter> = '<value>' ;
 * This hooks should return DefElem object, if the combination of parameter name and
 * configuration strings are available for the PgACE implementation.
 * If it returns NULL, a syntax error will be occured.
 *
 * @defname : given <parameter> string
 * @value   : given <value> string
 */
static inline DefElem *pgaceGramAlterDatabase(char *defname, char *value) {
	return NULL;
}

/*
 * pgaceAlterDatabasePrepare() is called to check whether the DefElem object is generated
 * in the above pgaceGramAlterDatabase(), or not. It should return true, if the given
 * defname is available.
 *
 * @defname : <parameter name> in null terminated string
 */
static inline bool pgaceAlterDatabasePrepare(char *defname) {
	return false;
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

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/

/*
 * pgaceCallFunction() is called before execution of SQL function
 * explicitly required by clients.
 *
 * @finfo    : FmgrInfo object for the target function
 * @as_query : true, if the function is used as a part of queries
 */
static inline void pgaceCallFunction(FmgrInfo *finfo, bool as_query) {
	/* do nothing */
}

/*
 * pgacePreparePlanCheck() is called before foreign key/primary key constraint checks,
 * at ri_PlanCheck(). PgACE implementation can return its opaque data for any purpose.
 *
 * @rel : the target relation in which a constraint is configured
 */
static inline Datum pgacePreparePlanCheck(Relation rel) {
	return (Datum) 0;
}

/*
 * pgaceRestorePlanCheck() is called after foreign key/primary key constraint checks,
 * at ri_PlanCheck(). PgACE implementation can use an opaque data generated in the above
 * pgacePreparePlanCheck().
 *
 * @rel         : the target relation in which a constraint is configured
 * @pgace_saved : an opaque data returned from pgacePreparePlanCheck()
 */
static inline void pgaceRestorePlanCheck(Relation rel, Datum pgace_saved) {
	/* do nothing */
}

/*
 * pgaceGramAlterFunction() is called when yacc/lex engine detect the following statement:
 *     ALTER FUNCTION <function name> (<argtype> ...) <parameter> = <value> ;
 * This hooks should return DefElem object, if the combination of parameter name and
 * value strings are available for the PgACE implementation.
 * If it returns NULL, a syntax error will be occured.
 *
 * @defname : given <parameter> string
 * @value   : given <value> string
 */
static inline DefElem *pgaceGramAlterFunction(char *defname, char *value) {
	return NULL;
}

/*
 * pgaceAlterFunctionPrepare() is called to check whether the DefElem object is generated
 * in the above pgaceGramAlterFunction(), or not. It should return true, if the given
 * defname is matched.
 *
 * @defname : <parameter name> in null terminated string
 */
static inline bool pgaceAlterFunctionPrepare(char *defname) {
	return false;
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
 * pgaceGramAlterTable() is called when yacc/lex engine detect the following statement:
 *     ALTER TABLE <table name> [ALTER <column name>] <parameter> = <value> ;
 * These hooks should return AlterTableCmd object, if the combination of parameter
 * and value strings are available for the PgACE implementation.
 * If it returns NULL, a syntax error will be occured.
 *
 * @colName : given column name. If NULL is given, it means [ALTER <column name>] is
 *            omitted in the statement.
 * @key     : given <parameter> string
 * @value   : given <value> string
 */
static inline AlterTableCmd *pgaceGramAlterTable(char *colName, char *key, char *value) {
	return NULL;
}

/*
 * pgaceAlterTablePrepare() is called to check whether the given AlterTableCmd object
 * is generated in the above pgaceGramAlterTable(), or not.
 * It should return true, if the given AlterTableCmd is matched.
 *
 * @rel : the target relation
 * @cmd : given AlterTableCmd object
 */
static inline bool pgaceAlterTablePrepare(Relation rel, AlterTableCmd *cmd) {
	return false;
}

/*
 * pgaceAlterTable() is called to modify table/column. The PgACE implementation
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
 *
 * @loid        : identifier of the large object
 * @lo_security : security attribute of the large object
 */
static inline void pgaceLargeObjectGetSecurity(Oid loid, Oid lo_security) {
	/* do nothing */
}

/*
 * pgaceLargeObjectSetSecurity() is called when lo_set_security() is executed
 *
 * @loid         : identifier of the large object
 * @old_security : previous security attribute of the large object 
 * @new_security : new security attribute of the large object
 */
static inline void pgaceLargeObjectSetSecurity(Oid loid, Oid old_security, Oid new_security) {
	/* do nothing */
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
 * @rel   : pg_largeobject relation opened with RowExclusiveLock
 * @tuple : one of the tuples within the target large object
 * @lobj  : large object descriptor which has uninitialized security attribute
 */
static inline void pgaceLargeObjectOpen(Relation rel, HeapTuple tuple, LargeObjectDesc *lobj) {
	/* do nothing */
}

/*
 * pgaceLargeObjectRead is called when they read from a large object
 *
 * @rel   : pg_largeobject relation opened with AccessShareLock
 * @tuple : a tuple within the target large object
 * @lobj  : large object descriptor
 */
static inline void pgaceLargeObjectRead(Relation rel, HeapTuple tuple, LargeObjectDesc *lobj) {
	/* do nothing */
}

/*
 * pgaceLargeObjectWrite() is called when they write to a large object
 *
 * @rel   : pg_largeobject relation opened with RowExclusiveLock
 * @tuple : a tuple within the target large object
 * @lobj  : large object descriptor
 */
static inline void pgaceLargeObjectWrite(Relation rel, HeapTuple tuple, LargeObjectDesc *lobj) {
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
 * PgACE implementation can use pgaceSecurityLabelIn() hook to translate
 * a input security label from external representation into internal one.
 * If no translation is necessary, it have to return @seclabel as is.
 *
 * @seclabel : security label being input
 */
static inline char *pgaceSecurityLabelIn(char *seclabel) {
	return "unlabeled";
}

/*
 * PgACE implementation can use pgaceSecurityLabelOut() hook to translate
 * a security label in internal representation into external one.
 * If no translation is necessary, it have to return @seclabel as is.
 *
 * @seclabel : security label being output
 */
static inline char *pgaceSecurityLabelOut(char *seclabel) {
	return "unlabeled";
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
 * generated tuple with in pg_security
 *
 * @early_mode : true, if pg_security is not generated yet (only bootstrap mode)
 */
static inline Oid pgaceSecurityLabelOfLabel(bool early_mode) {
	return InvalidOid;
}

/******************************************************************
 * Extended node type hooks
 ******************************************************************/

/*
 * If PgACE implementation requires new node type, a method to copy object.
 * pgaceCopyObject() provides a hook to copy new node typed object.
 * If a given object (@orig) has a tag extended by PgACE implementation,
 * it have to copy and return it.
 * If it returns NULL, @orig is not available for the PgACE implementation.
 *
 * @orig : a object which to copy
 */
static inline Node *pgaceCopyObject(Node *orig) {
	return NULL;
}

/*
 * pgaceOutObject() provides a hook to translate a object to text representation.
 * If a given object (@node) has a tag extended by PgACE implementation, it have
 * to put a text representation into StringInfo.
 * If it returns false, @node is not available for the PgACE implementation.
 *
 * @str  : StringInfo which to put the text representation
 * @node : a object that text representation is required
 */
static inline bool pgaceOutObject(StringInfo str, Node *node) {
	return false;
}

#endif

/* writable system column support */
extern void pgaceTransformSelectStmt(List *targetList);
extern void pgaceTransformInsertStmt(List **p_icolumns, List **p_attrnos, List *targetList);

/* SQL functions related to security label */
extern Datum security_label_in(PG_FUNCTION_ARGS);
extern Datum security_label_out(PG_FUNCTION_ARGS);
extern Datum security_label_raw_in(PG_FUNCTION_ARGS);
extern Datum security_label_raw_out(PG_FUNCTION_ARGS);
extern Datum text_to_security_label(PG_FUNCTION_ARGS);
extern Datum security_label_to_text(PG_FUNCTION_ARGS);

/* obsolete interface */
extern Oid early_security_label_to_sid(char *context);
extern Oid security_label_to_sid(char *context);
extern char *early_sid_to_security_label(Oid sid);
extern char *sid_to_security_label(Oid sid);
