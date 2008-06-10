/*
 * include/security/pgace.h
 *    headers for PostgreSQL Access Control Extension (PGACE)
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
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
 * The definitions of PGACE hooks are follows:
 *
 * These are declared as static inline functions which give us no effect
 * in the default (no security modules are enabled), and independent from
 * its platform.
 *
 * The purpose of PGACE framework is to provide a security subsystems
 * common hooks to apply its access controls, and minimize the impact
 * to add a new security subsystem.
 *
 * (*) We calls the security subsystem implemented on PGACE framework
 *     as "the guest", in this comment.
 *
 * When a security module uses this framework, is has to add a #ifdef
 * ... #endif block into the needed hooks, as follows:
 * 
 * ------------
 * static inline bool
 * pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
 *                      bool is_internal, bool with_returning)
 * {
 * #ifdef HAVE_SELINUX
 *     if (sepgsqlIsEnabled())
 *         return sepgsqlHeapTupleInsert(rel, tuple, is_internal, with_returning);
 * #endif
 * #ifdef HAVE_FOO_SECURITY
 *     if (fooIsEnabled())
 *         return fooHeapTupleInsert(rel, tuple, is_internal, with_returning);
 * #endif
 *     return true;
 * }
 * ____________
 *
 * It can invokes specific security subsystem and the callee makes its decision
 * whether the required access it allowed, or not.
 * When no security module is available, these hooks have to keep the default
 * behaivior to keep compatibility. In this case,  pgaceHeapTupleInsert() has
 * to return 'true'.
 *
 * Any hook has a comment to show the purpose of itself.
 * Please look at this one to understand each hooks.
 */

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
 * Initialization hooks
 ******************************************************************/

/*
 * pgaceShmemSize
 *
 * This hook has to return the size of shared memory required
 * by the guest. If it needs no shared memory region, it should
 * return 0.
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
 * pgaceInitialize
 *
 * This hook is invoked when a new PostgreSQL instance is created.
 * The guest can use this hook to initialize itself.
 * 
 * is_bootstrap is true, if bootstraping mode.
 */
static inline void
pgaceInitialize(bool is_bootstrap)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
	{
		sepgsqlInitialize(is_bootstrap);
		return;
	}
#endif
	/* do nothing */
}

/*
 * pgaceInitialize
 *
 * The guest can create a worker process in this hook, if necessary.
 * (currently, PGACE does not support multiple worker processes.)
 *
 * This hooks has to return the PID of child process. It is managed
 * by postmaster in the same way to manage the other children.
 * So, the worker process has to be available to handle signals.
 *
 * If unnecessary, it has to return (pid_t) 0.
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
 * pgaceProxyQuery
 *
 * This hook is invoked just after query is rewritten.
 *
 * The guest can check/modify/replace given query trees in this
 * hook, if necessary.
 * queryList is a list of Query object processes by rewriter.
 */
static inline List *
pgaceProxyQuery(List *queryList)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlProxyQuery(queryList);
#endif
	return queryList;
}

/*
 * pgaceIsAllowPlannerHook
 *
 * The guest can control whether planner_hook is available, or not.
 * It returns false, if it is not allowed to apply planner_hook.
 *
 * The purpose of this hook is to make sure pgace opaque data are delivered
 * to PlannedStmt::pgaceItem and Scan::pgaceTuplePerms, because they are
 * copied in standard_planner(). Overriding planner_hook has a possibility
 * to prevent the guest works correctly.
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
 * pgaceExecutorStart
 *
 * This hook is invoked on the head of ExecutorStart().
 *
 * The arguments of this hook are come from the ones of ExecutorStart
 * as is.
 */
static inline void
pgaceExecutorStart(QueryDesc *queryDesc, int eflags)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
	{
		Assert(queryDesc->plannedstmt != NULL);
		sepgsqlVerifyQuery(queryDesc->plannedstmt, eflags);
		return;
	}
#endif
	/* do nothing */
}

/*
 * pgaceExecScan
 *
 * This hook is invoked on ExecScan for each tuple fetched.
 * The guest can check its visibility, and can skip to scan the given
 * tuple. If this hook returns false, the tuple is filtered from the
 * result set or the target of updates/deletion.
 *
 * Otherwise, it has to return true.
 *
 * The guest can refer Scan::pgaceTuplePerms (declared as uint32).
 * It is a copy come from RangeTblEntry::pgaceTuplePerms set in
 * the previous phase. It can be used to mark what permissions are
 * required to scanned tuples.
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
 * pgaceProcessUtility
 *
 * This hooks is invoked on the head of ProcessUtility().
 */
static inline void
pgaceProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
	{
		sepgsqlProcessUtility(parsetree, params, isTopLevel);
		return;
	}
#endif
}

/*
 * pgaceEvaluateParams
 *
 * This hook is invoked just before parameter lists are evaluated
 * at EvaluateParams().
 */
static inline void
pgaceEvaluateParams(List *params)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
	{
		sepgsqlEvaluateParams(params);
		return;
	}
#endif
}


/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/

/*
 * pgaceHeapTupleInsert
 *
 * This hooks is invoked just before a new tuple is inserted.
 * If it returns false, inserting the given tuple is skipped.
 * (or generates an error, if we cannot skip it simply.)
 *
 * The guest has to set a security attribute of a newly inserted
 * tuple, if necessary and when user does not specify it explicitly.
 *
 * arguments:
 * - rel is the target relation to be inserted.
 * - tuple is the new tuple to be inserted.
 * - is_internal is a bool to show whether it directly come from
 *   user's query, or not.
 * - with_returning is a bool to show whether this INSERT statement
 *   has RETURNING clause, or not.
 */
static inline bool
pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
					 bool is_internal, bool with_returning)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleInsert(rel, tuple,
									  is_internal,
									  with_returning);
#endif
	return true;
}

/*
 * pgaceHeapTupleUpdate
 *
 * This hook is invoked just before a tuple is updated.
 * If it returns false, updating the given tuple is skipped.
 * (or generates an error, if we cannot skip it simply.)
 *
 * The guest has to preserve a security attribute of the updated
 * tuple, if necessary and when user specify its new security
 * attribute explicitly.
 *
 * arguments:
 * - rel is the target relation to be updated.
 * - otid is the ItemPointer of the tuple with older version.
 * - newtup is the tuple to be updated.
 * - is_internal is a bool to show whether it directly come from
 *   user's query, or not.
 * - with_returning is a bool to show whether this INSERT statement
 *   has RETURNING clause, or not.
 */
static inline bool
pgaceHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
					 bool is_internal, bool with_returning)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleUpdate(rel, otid, newtup,
									  is_internal,
									  with_returning);
#endif
	return true;
}

/*
 * pgaceHeapTupleDelete
 *
 * This hook is invoked just before a tuple is deleted.
 * If it returns false, deleting the given tuple is skipped.
 * (or generates an error, if we cannot skip it simply.)
 *
 * arguments:
 * - rel is the target relation to be deleted.
 * - otid is the ItemPointer of the tuple to be deleted.
 * - is_internal is a bool to show whether it directly come from
 *   user's query, or not.
 * - with_returning is a bool to show whether this INSERT statement
 *   has RETURNING clause, or not.
 */
static inline bool
pgaceHeapTupleDelete(Relation rel, ItemPointer otid,
					 bool is_internal, bool with_returning)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleDelete(rel, otid,
									  is_internal,
									  with_returning);
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
	/* do nothing */
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
	/* do nothing */
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
	/* do nothing */
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
	{
		sepgsqlCopyTable(rel, attNumList, isFrom);
		return;
	}
#endif
	/* do nothing */
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
		return sepgsqlCopyToTuple(rel, attNumList, tuple);
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

static inline void
pgaceLargeObjectCreate(Relation rel, HeapTuple tuple)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectCreate(rel, tuple);
#endif
	/* do nothing */
}

/*
 * LargeObjectDrop() iterates simple_heap_delete(), pgaceItem is kept
 * in a series of loop
 */
static inline void
pgaceLargeObjectDrop(Relation rel, HeapTuple tuple, bool is_first, Datum *pgaceItem)
{
#ifdef HAVE_SELINUX
    if (sepgsqlIsEnabled())
		sepgsqlLargeObjectDrop(rel, tuple, is_first, pgaceItem);
#endif
	/* do nothing */
}

/*
 * returning 'false' means this page should be dealt as a hole.
 */
static inline bool
pgaceLargeObjectRead(Relation rel, HeapTuple tuple, bool is_first, Datum *pgaceItem)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectRead(rel, tuple, is_first, pgaceItem);
#endif
	return true;
}

static inline void
pgaceLargeObjectWrite(Relation rel, Relation idx,
					  HeapTuple newtup, HeapTuple oldtup,
					  bool is_first, Datum *pgaceItem)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectWrite(rel, idx, newtup, oldtup, is_first, pgaceItem);
#endif
	/* do nothing */
}

static inline void
pgaceLargeObjectImport(Oid loid, int fdesc, const char *filename)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectImport(loid, fdesc, filename);
#endif
	/* do nothing */
}

static inline void
pgaceLargeObjectExport(Oid loid, int fdesc, const char *filename)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectExport(loid, fdesc, filename);
#endif
	/* do nothing */
}

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

static inline void
pgaceLargeObjectSetSecurity(Relation rel, HeapTuple tuple, Oid security_id,
							bool is_first, Datum *pgaceItem)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectSetSecurity(rel, tuple, security_id, is_first, pgaceItem);
#else
	elog(ERROR, "PGACE: There is no guest module.");
#endif
}



/******************************************************************
 * Security Label hooks
 ******************************************************************/

static inline char *
pgaceTranslateSecurityLabelIn(char *seclabel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlTranslateSecurityLabelIn(seclabel);
#endif
	return pstrdup("unlabeled");
}

static inline char *
pgaceTranslateSecurityLabelOut(char *seclabel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlTranslateSecurityLabelOut(seclabel);
#endif
	return pstrdup("unlabeled");
}

static inline char *
pgaceValidateSecurityLabel(char *seclabel)
{
#ifdef HAVE_SELINUX
	if (sepgsqlIsEnabled())
		return sepgsqlValidateSecurityLabel(seclabel);
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

extern Oid pgaceSecurityLabelToSid(char *label);

extern char *pgaceSidToSecurityLabel(Oid security_id);

extern char *pgaceLookupSecurityLabel(Oid security_id);

/* Extended SQL statements related */
extern List *pgaceRelationAttrList(CreateStmt *stmt);

extern void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple,
									  List *pgace_attr_list);
extern void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple,
									   List *pgace_attr_list);
extern void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd);

#endif // PGACE_H
