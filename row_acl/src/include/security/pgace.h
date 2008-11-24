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
#include "storage/large_object.h"
#include "utils/builtins.h"
#include "utils/rel.h"

#ifdef HAVE_SELINUX
#include "security/sepgsql.h"
#endif
#ifdef HAVE_ROW_ACL
#include "security/row_acl.h"
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
 * When a security module uses this framework, is has to add a #if .. #endif
 * block into the needed hooks, as follows:
 * 
 * ------------
 * static inline bool
 * pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
 *                      bool is_internal, bool with_returning)
 * {
 * #if defined(HAVE_SELINUX)
 *     if (sepgsqlIsEnabled())
 *         return sepgsqlHeapTupleInsert(rel, tuple,
 *                                       is_internal,
 *                                       with_returning);
 * #elif defined(HAVE_FOO_SECURITY)
 *     if (fooIsEnabled())
 *         return fooHeapTupleInsert(rel, tuple,
 *                                   is_internal,
 *                                   with_returning);
 * #endif
 *     return true;
 * }
 * ____________
 *
 * It can invokes specific security subsystem and the callee makes
 * its decision whether the required access it allowed, or not.
 * When no security module is available, these hooks have to keep
 * the default behaivior to keep compatibility.
 * In this case,  pgaceHeapTupleInsert() has to return 'true'.
 *
 * Any hook has a comment to show the purpose of itself.
 * Please look at this one to understand each hooks.
 */

/******************************************************************
 * Shows the PGACE guest identifier
 ******************************************************************/

/*
 * pgaceSecurityFeatureIdentity
 *
 * This hook has to return unique identifier of the PGACE guest.
 * A GUC parameter of 'pgace_security_feature' shows this value.
 */

static inline const char *
pgaceSecurityFeatureIdentity(void)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return "selinux";
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return "rowacl";
#endif
	return "nothing";
}

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
#if defined(HAVE_SELINUX)
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlInitialize(is_bootstrap);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		rowaclInitialize(is_bootstrap);
#endif
}

/*
 * pgaceStartupWorkerProcess
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
#if defined(HAVE_SELINUX)
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlProxyQuery(queryList);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclProxyQuery(queryList);
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return false;
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return false;
#endif
	return true;
}

/*
 * pgaceIsAllowExecutorRunHook
 *
 * The guest can control ExecutorRun_hook can be available, or not.
 * It returns false, if it is not allowed to apply ExecutorRun_hook.
 *
 * The purpose of this hook is to make sure the standard_ExecutorRun()
 * is invoked, because several important hooks are invoked from the path.
 * Overriding ExecutorRun_hook has a possibility to prevent the guest
 * works correctly.
 */
static inline bool
pgaceIsAllowExecutorRunHook(void)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return false;
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlVerifyQuery(queryDesc->plannedstmt, eflags);
#endif
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlExecScan(scan, rel, slot);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclExecScan(scan, rel, slot);
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlProcessUtility(parsetree, params, isTopLevel);
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlEvaluateParams(params);
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleInsert(rel, tuple,
									  is_internal,
									  with_returning);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclHeapTupleInsert(rel, tuple,
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleUpdate(rel, otid, newtup,
									  is_internal,
									  with_returning);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclHeapTupleUpdate(rel, otid, newtup,
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
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlHeapTupleDelete(rel, otid,
									  is_internal,
									  with_returning);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclHeapTupleDelete(rel, otid,
									 is_internal,
									 with_returning);
#endif
	return true;
}

/******************************************************************
 * Extended SQL statement hooks
 ******************************************************************/

/*
 * PGACE framework provides its guest facilities to manage security
 * attribute of database object, using an extended SQL statement.
 *
 * For example:
 *   CREATE TABLE tbl (
 *       x  integer,
 *       y  text
 *   ) CONTEXT = 'system_u:object_r:sepgsql_ro_table_t:Classified',
 *
 * In SE-PostgreSQL, this statement enables to create a new table
 * with explicitly specified security attribute by CONTEXT = 'xxx'
 * clause. We call the clause as a "security attribute modifier".
 *
 * The series of hooks enables the guest to handle the given
 * security attribute and apply it on the specified database
 * object.
 * 
 * The guest can apply this feature on the following statement:
 *
 * CREATE DATABASE <database>
 * ALTER DATABASE <database>
 * CREATE TABLE <table>
 * ALTER TABLE <table>
 * ALTER TABLE <table> ALTER <column>
 * CREATE FUNCTION <function>
 * ALTER FUNCTION <function>
 */

/*
 * pgaceGramSecurityItem
 *
 * This hook is invoked during parsing a give query from parser/gram.y,
 * and it generates a DefElem object which holds explicitly specified
 * security attribute. If the guest support the feature of security
 * attribute modifier, this hook has to check whether the given clause
 * is appropriate, or not.
 * 
 * In the following exmaple case:
 *   CREATE TABLE tbl (
 *       x  integer,
 *       y  text
 *   ) CONTEXT = 'system_u:object_r:sepgsql_ro_table_t:Classified',
 *
 * This hook is invoked with "context" as an argument of defname
 * and "system_u:object_r:sepgsql_ro_table_t:Classified" as an
 * argument of value, and has to check whether it is appropriate
 * as a security attribute modifier, or not.
 * If OK, the hook generates a DefElem object which contains
 * the given context, and returns it.
 *
 * To return NULL means that "This clause is not a security attribute
 * modifier", then it makes an error.
 */
static inline DefElem *
pgaceGramSecurityItem(char *defname, char *value)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlGramSecurityItem(defname, value);
#endif
	return NULL;
}

/*
 * pgaceIsGramSecurityItem
 *
 * This hook checks whether the given DefElem object means security
 * attribute modifier generated at pgaceGramSecurityItem(), or not.
 * If OK, it returns true.
 */
static inline bool
pgaceIsGramSecurityItem(DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlIsGramSecurityItem(defel);
#endif
	return false;
}

/*
 * The series of following hooks has three arguments.
 * - rel is an opened relation of the target system catalog.
 * - tuple is a new tuple to be inserted/updated.
 * - defel is a security attribute modifier generated at
 *   pgaceGramSecurityItem().
 */

/*
 * pgaceGramCreateRelation
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before inserting a new tuple into pg_class system catalog on
 * the processing of CREATE TABLE.
 * The guest can attach the required security attribute for the given
 * tuple which means a new relation.
 */
static inline void
pgaceGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramCreateRelation(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at CREATE TABLE: unavailable")));
}

/*
 * pgaceGramCreateAttribute
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before inserting a new tuple into pg_attribute system catalog on
 * the processing of CREATE TABLE.
 * The guest can attach the required security attribute for the given
 * tuple which means a new column.
 */
static inline void
pgaceGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramCreateAttribute(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at CREATE TABLE column: unavailable")));
}

/*
 * pgaceGramAlterRelation
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before updating an older tuple of pg_class system catalog on
 * the processing of ALTER TABLE.
 * The guest can attach the required security attribute for the given
 * tuple which means a table.
 */
static inline void
pgaceGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramAlterRelation(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at ALTER TABLE: unavailable")));
}

/*
 * pgaceGramAlterAttribute
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before updating an older tuple of pg_attribute system catalog on
 * the processing of ALTER TABLE.
 * The guest can attach the required security attribute for the given
 * tuple which means a column.
 */
static inline void
pgaceGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramAlterAttribute(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at ALTER TABLE column: unavailable")));
}

/*
 * pgaceGramCreateDatabase
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before inserting a new tuple into pg_database system catalog on
 * the processing of CREATE DATABASE.
 * The guest can attach the required security attribute for the given
 * tuple which means a database.
 */
static inline void
pgaceGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramCreateDatabase(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at CREATE DATABASE: unavailable")));
}

/*
 * pgaceGramAlterDatabase
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before updating an older tuple of pg_database system catalog on
 * the processing of ALTER DATABASE.
 * The guest can attach the required security attribute for the given
 * tuple which means a database.
 */
static inline void
pgaceGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramAlterDatabase(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at ALTER DATABASE: unavailable")));
}

/*
 * pgaceGramCreateFunction
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before inserting a new tuple into pg_proc system catalog on
 * the processing of CREATE FUNCTION.
 * The guest can attach the required security attribute for the given
 * tuple which means a function.
 */
static inline void
pgaceGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramCreateFunction(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at CREATE FUNCTION: unavailable")));
}

/*
 * pgaceGramAlterFunction
 *
 * This hook invoked to apply an explicitly specified security attribute
 * just before updating an older tuple of pg_proc system catalog on
 * the processing of ALTER FUNCTION.
 * The guest can attach the required security attribute for the given
 * tuple which means a function.
 */
static inline void
pgaceGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlGramAlterFunction(rel, tuple, defel);
		return;
	}
#endif
	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("security extention at ALTER FUNCTION: unavailable")));
}

/*
 * pgaceGramRelationOption
 *
 * This hook is invoked to apply security feature specific relation options.
 * If you can find any proper options, please return true, elsewhere false.
 */
static inline bool
pgaceGramRelationOption(const char *key, const char *value,
						StdRdOptions *result, bool validate)
{
#if defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclGramRelationOption(key, value, result, validate);
#endif
	return false;
}

/******************************************************************
 * DATABASE related hooks
 ******************************************************************/

/*
 * pgaceSetDatabaseParam
 *
 * This hook is invoked just before putting a new value on a GUC
 * variable.
 *
 * arguments:
 * - name is a name of GUC variable.
 * - argstring is its new value. NULL means user tries to reset
 *   the given GUC variable.
 */
static inline void
pgaceSetDatabaseParam(const char *name, char *argstring)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlSetDatabaseParam(name, argstring);
#endif
}

/*
 * pgaceGetDatabaseParam
 *
 * This hook is invoked just before reffering a GUC variable.
 *
 * arguments:
 * - name is a name of GUC variable.
 */
static inline void
pgaceGetDatabaseParam(const char *name)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlGetDatabaseParam(name);
#endif
}

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/

/*
 * pgaceCallFunction
 *
 * This hook is invoked just before execute a function as a part
 * of the query. It provides a FmgrInfo object used to execute
 * function, and the guest can store an opaque data within
 * FmgrInfo::fn_pgaceItem.
 */
static inline void
pgaceCallFunction(FmgrInfo *finfo)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, false);
#endif
}

/*
 * pgaceCallFunctionTrigger
 *
 * This hook is invoked just before executing trigger function.
 * If it returns false, the trigger function is not invoked and
 * caller receives a NULL tuple as a result.
 * (It also means skip to update/delete the tuple in BR-triggers.)
 *
 * The guest can refer FmgrInfo and TriggerData object to make
 * its decision.
 */
static inline bool
pgaceCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlCallFunctionTrigger(finfo, tgdata);
#endif
	return true;
}

/*
 * pgaceCallFunctionFastPath
 *
 * This hook is invoked just before executing a function in
 * fast path.
 */
static inline void
pgaceCallFunctionFastPath(FmgrInfo *finfo)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlCallFunction(finfo, true);
#endif
}

/*
 * pgaceBeginPerformCheckFK
 *
 * This hook is invoked just before performing FK constraint checks.
 * The guest can change its internal state during the checks.
 * The major purpose of this function is to prevent violation of
 * integrity consistentency violation due to row-level access control.
 * If the guest requires an opaque data, it should be returned then
 * it will be delivered via pgaceEndPerformCheckFK().
 */
static inline Datum
pgaceBeginPerformCheckFK(Relation rel, bool is_primary, Oid save_userid)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlBeginPerformCheckFK(rel, is_primary, save_userid);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		rowaclBeginPerformCheckFK(rel, is_primary, save_userid);
#endif
	return PointerGetDatum(NULL);
}

/*
 * pgaceEndPerformCheckFK
 *
 * This hook is invoked just after performing FK constraint checks.
 * The guest can restore its internal state using this hook.
 */
static inline void
pgaceEndPerformCheckFK(Relation rel, Datum save_pgace)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlEndPerformCheckFK(rel, save_pgace);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		rowaclEndPerformCheckFK(rel, save_pgace);
#endif
}

/******************************************************************
 * TABLE related hooks
 ******************************************************************/

/*
 * pgaceLockTable
 *
 * This hook is invoked when user tries to LOCK a table explicitly.
 * The argument of relid shows the target relation id.
 */
static inline void
pgaceLockTable(Oid relid)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLockTable(relid);
#endif
}

/******************************************************************
 * COPY TO/COPY FROM statement hooks
 ******************************************************************/

/*
 * pgaceCopyTable
 *
 * This hook is invoked before executing COPY TO/COPY FROM statement,
 * to give the guest a chance to check tables/columns appeared in.
 *
 * arguments:
 * - rel is the target relation of this COPY TO/FROM statement.
 *   It can be NULL, when COPY (SELECT ...) TO ... is given.
 * - attNumList is a list of attribute number
 * - isFrom is a bool to show the direction of the COPY
 */
static inline void
pgaceCopyTable(Relation rel, List *attNumList, bool isFrom)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlCopyTable(rel, attNumList, isFrom);
#endif
}

/*
 * pgaceCopyFile
 *
 * This hook is invoked just after a target file is opened
 * at COPY TO/COPY FROM statement to give the guest a chance to
 * check whether it allows to read/write the file.
 *
 * arguments:
 * - rel is the target relation of this COPY TO/FROM statement.
 *   It can be NULL, when COPY (SELECT ...) TO ... is given.
 * - isFrom is a bool to show the direction of the COPY
 * - fdesc is the file descriptor of the target file opened.
 * - filename is the filename of fdesc
 */
static inline void
pgaceCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlCopyFile(rel, fdesc, filename, isFrom);
#endif
}

/*
 * pgaceCopyToTuple
 *
 * This hook is invoked just before output of a fetched tuple on
 * processing COPY TO statement, to give the guest a chance to make
 * a decision whether the given tuple is visible, or not.
 * If it returns false, the given tuple is not exported, as if it
 * does not exist on the target relation.
 * Elsewhere, 
 *
 * arguments:
 * - rel is the target relation of this 
 * - attNumList is a list of attribute number
 * - tuple is a tuple to be checked
 */
static inline bool
pgaceCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlCopyToTuple(rel, attNumList, tuple);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclCopyToTuple(rel, attNumList, tuple);
#endif
	return true;
}

/******************************************************************
 * Loadable shared library module hooks
 ******************************************************************/

/*
 * pgaceLoadSharedModule
 *
 * This hook is invoked before loading a shared library module,
 * to give the guest a change to confirm whether the required
 * module is safe, or not.
 *
 * This hook can be also invoked implicitly when a user tries
 * to call a function implemented within external modules.
 */
static inline void
pgaceLoadSharedModule(const char *filename)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLoadSharedModule(filename);
#endif
}

/******************************************************************
 * Binary Large Object (BLOB) hooks
 ******************************************************************/

/*
 * pgaceLargeObjectCreate
 *
 * This hooks is invoked just before the first tuple of a new large
 * object is inserted, to give the guest a change to make its
 * decision and attach proper security context for the tuple.
 *
 * The argument of rel is the opened pg_largeobject system catalog.
 */
static inline void
pgaceLargeObjectCreate(Relation rel, HeapTuple tuple)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectCreate(rel, tuple);
#endif
}

/*
 * pgaceLargeObjectDrop
 *
 * This hook is invoked just before each tuple of a large object
 * are deleted, to give the guest a change to make its decision.
 *
 * The argument of pgaceItem is an opaque data, the guest can
 * use it discreationally.
 */
static inline void
pgaceLargeObjectDrop(Relation rel, HeapTuple tuple, void **pgaceItem)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectDrop(rel, tuple, pgaceItem);
#endif
}

/*
 * pgaceLargeObjectRead
 *
 * This hook is invoked at the head of lo_read().
 * If the guest allows a large object to have non-uniform security
 * attributes (not a unique one for each page frame), using HeapTuple
 * related hooks are more recommendable.
 */
static inline void
pgaceLargeObjectRead(LargeObjectDesc *lodesc, int length)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectRead(lodesc, length);
#endif
}

/*
 * pgaceLargeObjectWrite
 *
 * This hook is invoked at the head of lo_write().
 */
static inline void
pgaceLargeObjectWrite(LargeObjectDesc *lodesc, int length)
{
#if defined(HAVE_SELINUX)
    if (sepgsqlIsEnabled())
		sepgsqlLargeObjectWrite(lodesc, length);
#endif
}

/*
 * pgaceLargeObjectTruncate
 *
 * This hook is invoked at the head of lo_truncate().
 */
static inline void
pgaceLargeObjectTruncate(LargeObjectDesc *lodesc, int offset)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectTruncate(lodesc, offset);
#endif
}

/*
 * pgaceLargeObjectImport
 *
 * This hook is invoked just before importing the given file.
 */
static inline void
pgaceLargeObjectImport(Oid loid, int fdesc, const char *filename)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectImport(loid, fdesc, filename);
#endif
}

/*
 * pgaceLargeObjectExport
 *
 * This hook is invoked just before exporting the given large object.
 */
static inline void
pgaceLargeObjectExport(Oid loid, int fdesc, const char *filename)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		sepgsqlLargeObjectExport(loid, fdesc, filename);
#endif
}

/*
 * pgaceLargeObjectGetSecurity
 *
 * This hook is invoked when user requires to run lo_get_security()
 * Note that PGACE assumes the security attribute of first page frame
 * of large object represents its security attribute.
 */
static inline void
pgaceLargeObjectGetSecurity(Relation rel, HeapTuple tuple)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlLargeObjectGetSecurity(rel, tuple);
		return;
	}
#endif
	elog(ERROR, "PGACE: There is no guest module available.");
}

/*
 * pgaceLargeObjectSetSecurity
 *
 * This hook is invoked when user requires to run lo_set_security(),
 * for each tuple within a given large object, which have unchecked
 * security attribute. In other word, PGACE does not require the guest
 * to check permission toward same security attribute twice, or more.
 */
static inline void
pgaceLargeObjectSetSecurity(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
	{
		sepgsqlLargeObjectSetSecurity(rel, newtup, oldtup);
		return;
	}
#endif
	elog(ERROR, "PGACE: There is no guest module available.");
}

/******************************************************************
 * Security Label hooks
 ******************************************************************/

/*
 * pgaceTupleDescHasSecurity
 *
 * This hook enables to control the value in TupleDesc->tdhassecurity.
 * If it returns true, sizeof(Oid) bytes are allocated at the header
 * of HeapTupleHeader structure.
 *
 * Don't trust Relation->rd_rel->relkind, because this hook can be
 * invoked from heap_create(), but it does not initialize relkind
 * member yet.
 *
 * The 'rel' argument can be NULL, when we make a decision for newly
 * created relation via SELECT INTO/CREATE TABLE AS. In this case,
 * relation options are delivered.
 */
static inline bool
pgaceTupleDescHasSecurity(Relation rel, List *relopts)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlTupleDescHasSecurity(rel, relopts);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclTupleDescHasSecurity(rel, relopts);
#endif
	return false;
}

/*
 * pgaceTranslateSecurityLabelIn
 *
 * This hook enables the guest to translate a text representation
 * of a given security attribute in external format into internal
 * raw-format. It is invoked when user specifies security attribute
 * explicitly in INSERT/UPDATE statement, to translate it into
 * raw-internal format.
 *
 * It has to return a palloc()'ed Cstring, as a raw-internal format.
 *
 * In SE-PostgreSQL it supports translation in MLS/MCS labels like:
 *   "system_u:object_r:sepgsql_table_t:SystemHigh"
 *     <-->  "system_u:object_r:sepgsql_table_t:s0:c0.c1023"
 */
static inline char *
pgaceTranslateSecurityLabelIn(char *seclabel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlTranslateSecurityLabelIn(seclabel);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclTranslateSecurityLabelIn(seclabel);
#endif
	return seclabel;
}

/*
 * pgaceTranslateSecurityLabelOut
 *
 * This hook enables the guest to translate a text representation
 * of a given security attribute in internal format into cosmetic
 * external format.
 */
static inline char *
pgaceTranslateSecurityLabelOut(char *seclabel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlTranslateSecurityLabelOut(seclabel);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclTranslateSecurityLabelOut(seclabel);
#endif
	return seclabel;
}

/*
 * pgaceValidateSecurityLabel
 *
 * This hook enables the guest to validate the given security attribute
 * in raw-internal format. If it is not available, the hook has to
 * return an alternative security attribute.
 */
static inline bool
pgaceCheckValidSecurityLabel(char *seclabel)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlCheckValidSecurityLabel(seclabel);
#elif defined(HAVE_ROW_ACL)
	if (rowaclIsEnabled())
		return rowaclCheckValidSecurityLabel(seclabel);
#endif
	return false;
}

/*
 * pgaceUnlabeledSecurityLabel
 *
 * This hooks allows the guest to provide an alternative security
 * attribute, when no valid text representation found on pg_security.
 * The hooks has to return an alternative attribute palloc()'ed.
 */
static inline char *
pgaceUnlabeledSecurityLabel(void)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlUnlabeledSecurityLabel();
#endif
	return NULL;
}

/*
 * pgaceSecurityLabelOfLabel
 *
 * This hook has to return the security attribute of a newly inserted
 * tuple withing pg_security system catalog. Note that we need a special
 * handling in the case of pg_security. If a new tuple requires a quite
 * new security attribute which is not on pg_security, its insertion
 * invokes one more insertion into pg_security. In the result, it makes
 * infinite function invocation.
 * This hook is used to avoid such a situation. The guest has to return
 * a text represented security attribute.
 */
static inline char *
pgaceSecurityLabelOfLabel(void)
{
#if defined(HAVE_SELINUX)
	if (sepgsqlIsEnabled())
		return sepgsqlSecurityLabelOfLabel();
#endif
	return NULL;
}

/******************************************************************
 * PGACE common facilities (not a hooks)
 ******************************************************************/

/* GUC parameter support */
extern const char *pgaceShowSecurityFeature(void);

/* Security Label Management */
extern void pgacePostBootstrapingMode(void);

extern Oid pgaceSecurityLabelToSid(char *label);

extern char *pgaceSidToSecurityLabel(Oid security_id);

extern Oid pgaceLookupSecurityId(char *label);

extern char *pgaceLookupSecurityLabel(Oid security_id);

/* Extended SQL statements related */
extern List *pgaceRelationAttrList(CreateStmt *stmt);

extern void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple,
									  List *pgace_attr_list);
extern void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple,
									   List *pgace_attr_list);
extern void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd);

/******************************************************************
 * SQL function declaration related to PGACE security framework
 ******************************************************************/

/*
 * SE-PostgreSQL SQL FUNCTIONS
 */
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_getservcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_range(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_range(PG_FUNCTION_ARGS);

#endif // PGACE_H
