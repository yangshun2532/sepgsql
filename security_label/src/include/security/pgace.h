
/*
 * include/security/pgace.h
 *	 headers for PostgreSQL Access Control Extensions (PGACE)
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef PGACE_H
#define PGACE_H

#include "access/htup.h"
#include "access/sysattr.h"
#include "commands/trigger.h"
#include "executor/execdesc.h"
#include "nodes/parsenodes.h"
#include "utils/builtins.h"
#include "utils/rel.h"

#ifdef HAVE_SELINUX
#include "security/sepgsql.h"
#endif

/*
 * SECURITY_SYSATTR_NAME is the name of system column name
 * for security attribute, defined in pg_config.h
 * If it is not defined, security attribute support is disabled
 *
 * see, src/include/pg_config.h
 */
#ifdef SECURITY_SYSATTR_NAME
#define pgaceIsSecuritySystemColumn(attno)		\
	((attno) == SecurityAttributeNumber ? true : false)
#else
#define pgaceIsSecuritySystemColumn(attno)		(false)
#endif

/******************************************************************
 * Initialize / Finalize related hooks
 ******************************************************************/

/*
 * pgaceShmemSize() have to return the size of shared memory segment
 * required by PGACE implementation. If no shared memory segment needed,
 * it should return 0.
 */
static inline Size
pgaceShmemSize(void)
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
static inline void
pgaceInitialize(bool is_bootstrap)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlInitialize(is_bootstrap);
#endif
	/* do nothing */
}

/*
 * pgaceStartupWorkerProcess() can fork a worker process
 */
static inline pid_t
pgaceStartupWorkerProcess(void)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlStartupWorkerProcess();
#endif
	return (pid_t) 0;
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
static inline List *
pgaceProxyQuery(List *queryList)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
	{
		List	   *newList = NIL;

		ListCell   *l;

		foreach(l, queryList)
		{
			Query	   *q = (Query *) lfirst(l);

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
static inline void
pgacePortalStart(Portal portal)
{
	/*
	 * do nothing
	 */
}

/*
 * pgaceIsAllowPlannerHook()
 *
 */
static inline bool
pgaceIsAllowPlannerHook(void)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return false;
#endif
	return true;
}

/*
 * pgaceExecutorStart() is called on the top of ExecutorStart().
 *
 * @queryDesc : a QueryDesc object given to ExecutorStart().
 * @eflags	  : eflags valus given to ExecutorStart().
 *				if EXEC_FLAG_EXPLAIN_ONLY is set, no real access will run.
 */
static inline void
pgaceExecutorStart(QueryDesc *queryDesc, int eflags)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
	{
		Assert(queryDesc->plannedstmt != NULL);
		sepgsqlVerifyQuery(queryDesc->plannedstmt, eflags);
	}
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceExecScan() is invoked on ExecScan() to apply tuple level access
 * controls. If this hook returns false, the give tuple is filtered from
 * the result set.
 */
static inline bool
pgaceExecScan(Scan *scan, Relation rel, TupleTableSlot *slot)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlExecScan(scan, rel, slot);
#endif
	return true;
}

/*
 * pgaceProcessUtility() is called on the top of ProcessUtility()
 */
static inline void
pgaceProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
	{
		sepgsqlProcessUtility(parsetree, params, isTopLevel);
	}
#endif
}

/*
 * pgaceEvaluateParams() is called on statement with parameter
 */
static inline void
pgaceEvaluateParams(List *params)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlEvaluateParams(params);
#endif
}


/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/

/*
 * pgaceHeapTupleInsert() is called when a new tuple attempt to be inserted.
 * If it returns false, this insertion of a new tuple will be cancelled.
 * However, it does not generate any error.
 *
 * @rel			   : the target relation
 * @tuple		   : the tuple attmpt to be inserted
 * @is_internal    : true, if this operation is invoked by system internal processes.
 * @with_returning : true, if INSERT statement has RETURNING clause.
 */
static inline bool
pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
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
 * @rel			   : the target relation
 * @otid		   : ItemPointer of the tuple to be updated
 * @newtup		   : the new contains of the updated tuple
 * @is_internal    : true, if this operation is invoked by system internal processes.
 * @with_returning : true, if INSERT statement has RETURNING clause.
 */
static inline bool
pgaceHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
					 bool is_internal, bool with_returning)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleUpdate(rel, otid, newtup, is_internal,
									  with_returning);
#endif
	return true;
}

/*
 * pgaceHeapTupleDelete() is called when a tuple attempt to be deleted.
 * If it returns false, this deletion will be cancelled.
 * However, it does not generate any error.
 *
 * @rel			   : the target relation
 * @otid		   : ItemPointer of the tuple to be deleted
 * @is_internal    : true, if this operation is invoked by system internal processes.
 * @with_returning : true, if INSERT statement has RETURNING clause.
 */
static inline bool
pgaceHeapTupleDelete(Relation rel, ItemPointer otid,
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
 * @value	: given <value> string
 */
static inline DefElem *
pgaceGramSecurityItem(char *defname, char *value)
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
static inline bool
pgaceIsGramSecurityItem(DefElem *defel)
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
static inline void
pgaceGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramCreateRelation(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGramCreateAttribute() is called to modify a tuple just before inserting
 * a new attribute with CREATE TABLE, if extended statement is used.
 *
 * @rel   : pg_attribute relation
 * @tuple : a tuple of new attribute
 * @defel : extended statement
 */
static inline void
pgaceGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramCreateAttribute(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGramAlterRelation() is called to modify a tuple just before updating
 * a relation with ALTER TABLE, if extended statement is used.
 *
 * @rel   : target relation
 * @tuple : a tuple of new relation
 * @defel : extended statement
 */
static inline void
pgaceGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramAlterRelation(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGramAlterAttribute() is called to modify a tuple just before updating
 * an attribute with ALTER TABLE, if extended statement is specified.
 *
 * @rel   : target relation
 * @tuple : a tuple of new attribute
 * @defel : extended statement
 */
static inline void
pgaceGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlGramAlterAttribute(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGramCreateDatabase() is called to modify a tuple just before inserting
 * a new database with CREATE DATABASE, if extended statement is used.
 *
 * @rel   : pg_database relation
 * @tuple : a tuple of the new database
 * @defel : extended statement
 */
static inline void
pgaceGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramCreateDatabase(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGramAlterDatabase() is called to modify a tuple just before updating
 * a database with ALTER DATABASE, if extended statement is used.
 *
 * @rel   : pg_database relation
 * @tuple : a tuple of the updated database
 * @defel : extended statement
 */
static inline void
pgaceGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramAlterDatabase(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGramCreateFunction() is called to modify a tuple just before inserting
 * a new function into pg_proc, if extended statement is used.
 *
 * @rel   : pg_proc relation
 * @tuple : a tuple of the new function
 * @defel : extended statement
 */
static inline void
pgaceGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramCreateFunction(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGramAlterFunction() is called to modify a tuple just before updating
 * a function with ALTER FUNCTION, if extended statement is used.
 *
 * @rel   : pg_proc relation
 * @tuple : a tuple of the function
 * @defel : extended statement
 */
static inline void
pgaceGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGramAlterFunction(rel, tuple, defel);
#endif
	/*
	 * do nothing
	 */
}

/******************************************************************
 * DATABASE related hooks
 ******************************************************************/

/*
 * pgaceSetDatabaseParam() is called when clients tries to set GUC variables
 *
 * @name   : The name of GUC variable
 * @argstr : The new valus of GUC variable. If argstr is NULL, it means
 *			 clients tries to reset the variable.
 */
static inline void
pgaceSetDatabaseParam(const char *name, char *argstring)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlSetDatabaseParam(name, argstring);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceGetDatabaseParam() is called when clients tries to refer GUC variables
 *
 * @name : The name of GUC variable
 */
static inline void
pgaceGetDatabaseParam(const char *name)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlGetDatabaseParam(name);
#endif
	/*
	 * do nothing
	 */
}

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/

/*
 * pgaceCallFunction() is called just before executing SQL function
 * as a part of query.
 *
 * @finfo	 : FmgrInfo object for the target function
 */
static inline void
pgaceCallFunction(FmgrInfo *finfo)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, false);
#endif
	/*
	 * do nothing
	 */
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
static inline bool
pgaceCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata)
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
static inline void
pgaceCallFunctionFastPath(FmgrInfo *finfo)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, true);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgacePreparePlanCheck() is called before foreign key/primary key constraint checks,
 * at ri_PlanCheck(). PGACE implementation can return its opaque data for any purpose.
 *
 * @rel : the target relation in which a constraint is configured
 */
static inline Datum
pgacePreparePlanCheck(Relation rel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlPreparePlanCheck(rel);
#endif
	return (Datum) 0;
}

/*
 * pgaceRestorePlanCheck() is called after foreign key/primary key constraint checks,
 * at ri_PlanCheck(). PGACE implementation can use an opaque data generated in the above
 * pgacePreparePlanCheck().
 *
 * @rel			: the target relation in which a constraint is configured
 * @pgace_saved : an opaque data returned from pgacePreparePlanCheck()
 */
static inline void
pgaceRestorePlanCheck(Relation rel, Datum pgace_saved)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlRestorePlanCheck(rel, pgace_saved);
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
static inline void
pgaceLockTable(Oid relid)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLockTable(relid);
#endif
	/*
	 * do nothing
	 */
}

/******************************************************************
 * COPY TO/COPY FROM statement hooks
 ******************************************************************/

/*
 * pgaceCopyTable() is called when COPY TO/COPY FROM statement is processed
 *
 * @rel		   : the target relation
 * @attNumList : the list of attribute numbers
 * @isFrom	   : true, if the given statement is 'COPY FROM'
 */
static inline void
pgaceCopyTable(Relation rel, List *attNumList, bool isFrom)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlCopyTable(rel, attNumList, isFrom);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceCopyToTuple() is called to check whether the given tuple should be
 * filtered, or not in the process of COPY TO statement.
 * If it returns false, the given tuple will be filtered from the result set
 *
 * @rel		   : the target relation
 * @attNumList : the list of attribute numbers
 * @tuple	   : the target tuple
 */
static inline bool
pgaceCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
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
static inline void
pgaceLoadSharedModule(const char *filename)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLoadSharedModule(filename);
#endif
	/*
	 * do nothing
	 */
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
static inline void
pgaceLargeObjectGetSecurity(Relation rel, HeapTuple tuple)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectGetSecurity(rel, tuple);
#else
	elog(ERROR, "PGACE: There is no guest module.");
#endif
}

/*
 * pgaceLargeObjectSetSecurity() is called when lo_set_security() is executed
 *
 * @tuple		: a tuple which is a part of the target largeobject.
 * @lo_security : new security attribute specified
 */
static inline void
pgaceLargeObjectSetSecurity(Relation rel, HeapTuple oldtup, HeapTuple newtup)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectSetSecurity(rel, oldtup, newtup);
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
static inline void
pgaceLargeObjectCreate(Relation rel, HeapTuple tuple)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectCreate(rel, tuple);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceLargeObjectDrop() is called when a large object is dropped once for
 * a large object
 *
 * @rel   : pg_largeobject relation opened with RowExclusiveLock
 * @tuple : one of the tuples within the target large object
 */
static inline void
pgaceLargeObjectDrop(Relation rel, HeapTuple tuple)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectDrop(rel, tuple);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceLargeObjectRead is called when they read from a large object
 *
 * @rel   : pg_largeobject relation opened with AccessShareLock
 * @tuple : the head tuple within the given large object
 */
static inline void
pgaceLargeObjectRead(Relation rel, HeapTuple tuple)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectRead(rel, tuple);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceLargeObjectWrite() is called when they write to a large object
 *
 * @rel    : pg_largeobject relation opened with RowExclusiveLock
 * @newtup : the head tuple within the given large object
 * @oldtup : the head tuple in older version, if exist
 */
static inline void
pgaceLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectWrite(rel, newtup, oldtup);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceLargeObjectTruncate() is called when they truncate a large object.
 *
 * @rel		: pg_largeobject relation opened with RowExclusiveLock
 * @loid	: large object identifier
 * @headtup : the head tuple to be truncated. NULL means this BLOB will be expanded.
 */
static inline void
pgaceLargeObjectTruncate(Relation rel, Oid loid, HeapTuple headtup)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectTruncate(rel, loid, headtup);
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceLargeObjectImport() is called when lo_import() is processed
 *
 * @fd : file descriptor to be inported
 */
static inline void
pgaceLargeObjectImport(int fd)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectImport();
#endif
	/*
	 * do nothing
	 */
}

/*
 * pgaceLargeObjectExport() is called when lo_import() is processed
 *
 * @fd	 : file descriptor to be exported
 * @loid : large object to be exported
 */
static inline void
pgaceLargeObjectExport(int fd, Oid loid)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectExport();
#endif
	/*
	 * do nothing
	 */
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
static inline char *
pgaceSecurityLabelIn(char *seclabel)
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
static inline char *
pgaceSecurityLabelOut(char *seclabel)
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
static inline char *
pgaceSecurityLabelCheckValid(char *seclabel)
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
 */
static inline char *
pgaceSecurityLabelOfLabel(void)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlSecurityLabelOfLabel();
#endif
	return pstrdup("unlabeled");
}

/******************************************************************
 * PGACE common facilities (not a hooks)
 ******************************************************************/

/* Security Label Management */
extern void pgacePostBootstrapingMode(void);

/* Extended SQL statements related */
extern List *pgaceRelationAttrList(CreateStmt *stmt);

extern void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple,
									  List *pgace_attr_list);
extern void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple,
									   List *pgace_attr_list);
extern void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd);

/* SQL functions */
extern Datum security_label_in(PG_FUNCTION_ARGS);

extern Datum security_label_out(PG_FUNCTION_ARGS);

extern Datum security_label_raw_in(PG_FUNCTION_ARGS);

extern Datum security_label_raw_out(PG_FUNCTION_ARGS);

extern Datum text_to_security_label(PG_FUNCTION_ARGS);

extern Datum security_label_to_text(PG_FUNCTION_ARGS);

extern Datum lo_get_security(PG_FUNCTION_ARGS);

extern Datum lo_set_security(PG_FUNCTION_ARGS);

#endif // PGACE_H
