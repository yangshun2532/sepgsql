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
#include "security/rowacl.h"
#include "storage/large_object.h"
#include "utils/builtins.h"
#include "utils/rel.h"

#ifdef HAVE_SELINUX
#include "security/sepgsql.h"
#endif

/*
 * pgace_feature : a parameter to choose an enhanced security feature
 */
typedef enum
{
	PGACE_FEATURE_NONE,
#ifdef HAVE_SELINUX
	PGACE_FEATURE_SELINUX,
#endif
} PgaceFeatureOpts;

extern int pgace_feature;

/*
 * The definitions of PGACE security hooks
 *
 * PGACE is PostgreSQL Access Control Extension.
 * These hooks are declared as static inline functions to give a guest
 * feature chances to make its decision on access controls.
 * Its purpose is to implement enhanced security features with minimum
 * impact to the core PostgreSQL codes. In generally, different security
 * feature has its own access control model, policy and granuality, but
 * they can share some of facilities.
 * The one is hooks injected on strategic points, and the other is 
 * management of security attribute of database objects.
 *
 * This header files declares security hooks. When you add your security
 * design, you should add its entry to "pgace_feature" option which can
 * be choosen by users, and update the hooks as follows:
 * 
 * ------------
 * static inline bool
 * pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
 *                      bool is_internal, bool with_returning)
 * {
 *     if (!rowaclHeapTupleInsert(rel, tuple,
 * 	                              is_internal,
 *                                with_returning))
 *         return false;
 * 
 *     switch (pgace_feature)
 *     {
 * #ifdef HAVE_SELINUX
 *     case PGACE_FEATURE_SELINUX:
 *         if (sepgsqlIsEnabled())
 *             return sepgsqlHeapTupleInsert(rel, tuple,
 *                                           is_internal,
 *                                           with_returning);
 *     break;
 * #endif
 * #ifdef HAVE_FOO_SECURITY
 *     case PGACE_FEATURE_FOO_SECURITY:
 *         return fooSecurityHeapTupleInsert(rel, tuple,
 *                                           is_internal,
 *                                           with_returning);
 *     break;
 * #endif
 *     default:
 *         break;
 *     }
 * return true;
 * }
 * ------------
 *
 * The Row-level Database ACLs feature is hardwired. It is a traditional
 * DAC policy in row level.
 * In addition, we allows users to choose an enhanced security feature
 * via GUC option "pgace_feature" on startup time.
 * If you add your implementation, its invocation should be deployed
 * as an option of switches. In this example, we add a new feature named
 * as "FOO_SECURITY". Its code is invoked on a new tuple is inserted into
 * relations.
 * We provides variable kind of hooks. If your security model does not
 * need anything on some of hooks, keep it as is. It does not give any
 * affects to the vanilla behavior.
 */

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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlShmemSize();
		break;
#endif
	default:
		break;
	}

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
	/* A wired DAC initialization */
	rowaclInitialize(is_bootstrap);

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlInitialize(is_bootstrap);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlStartupWorkerProcess();
		break;
#endif
	default:
		break;
	}

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
	/* A wired DAC check */
	queryList = rowaclProxyQuery(queryList);

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlProxyQuery(queryList);
		break;
#endif
	default:
		break;
	}

	return queryList;
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlExecutorStart(queryDesc, eflags);
		break;
#endif
	default:
		break;
	}
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
	/* A wired DAC check */
	if (!rowaclExecScan(scan, rel, slot))
		return false;

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlExecScan(scan, rel, slot);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlProcessUtility(parsetree, params, isTopLevel);
		break;
#endif
	default:
		break;
	}
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
	/* A wired DAC check */
	if (!rowaclHeapTupleInsert(rel, tuple,
							   is_internal,
							   with_returning))
		return false;

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlHeapTupleInsert(rel, tuple,
										  is_internal,
										  with_returning);
		break;
#endif
	default:
		break;
	}
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
	/* A wired DAC check */
	if (!rowaclHeapTupleUpdate(rel, otid, newtup,
							   is_internal,
							   with_returning))
		return false;

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlHeapTupleUpdate(rel, otid, newtup,
										  is_internal,
										  with_returning);
		break;
#endif
	default:
		break;
	}
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
	/* A wired DAC check */
	if (!rowaclHeapTupleDelete(rel, otid,
							   is_internal,
							   with_returning))
		return false;

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlHeapTupleDelete(rel, otid,
										  is_internal,
										  with_returning);
		break;
#endif
	default:
		break;
	}
	return true;
}

/******************************************************************
 * Extended SQL statement hooks
 ******************************************************************/

/*
 * pgaceIsGramSecurityItem
 *
 * PGACE framework provides its guest to manage security attribute
 * for some kind of database obejcts, using an enhanced SQL statement.
 *
 * For example:
 *   CREATE TABLE tbl (
 *       x  integer,
 *       y  text
 *   ) security_label = 'system_u:object_r:sepgsql_table_t:Classified';
 *
 * This hook is invoked during parsing given queries at parser/gram.y.
 * It generates a DefElem object which holds explicitly specified
 * security attribute. If working guest support the feature and the
 * given DefElem has correct pair of defname and argument string,
 * this hook should return true.
 * In ths above example, the given DefElem has "security_label" as
 * defname, and "system_u:object_r:sepgsql_table_t:Classified" as
 * its argument string.
 */
static inline bool
pgaceIsGramSecurityItem(DefElem *defel)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlIsGramSecurityItem(defel);
		break;
#endif
	default:
		break;
	}
	return false;
}

/*
 * The series of following hooks has three arguments.
 * - rel is an opened relation of the target system catalog.
 * - tuple is a new tuple to be inserted/updated.
 * - defel is a DefElem object checked in pgaceIsGramSecurityItem().
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramCreateRelation(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of table "
						"via CREATE TABLE")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramCreateAttribute(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of column "
						"via CREATE TABLE")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramAlterRelation(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of table "
						"via ALTER TABLE")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramAlterAttribute(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of column "
						"via ALTER TABLE")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramCreateDatabase(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of database "
						"via CREATE DATABASE")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramAlterDatabase(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of database "
						"via ALTER DATABASE")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramCreateFunction(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of function "
						"via CREATE FUNCTION")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlGramAlterFunction(rel, tuple, defel);
			return;
		}
		break;
#endif
	default:
		break;
	}

	if (defel)
		ereport(ERROR,
				(errcode(ERRCODE_PGACE_ERROR),
				 errmsg("unable to set security attribute of function "
						"via ALTER FUNCTION")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlSetDatabaseParam(name, argstring);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlGetDatabaseParam(name);
		break;
#endif
	default:
		break;
	}
}

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/

/*
 * pgaceCallFunction
 *
 * This hook is invoked when a function is invoked as a part
 * of the given query. It provides a FmgrInfo object of the
 * function, so the guest can store its opaque data within
 * FmgrInfo::fn_pgaceItem.
 */
static inline void
pgaceCallFunction(FmgrInfo *finfo)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlCallFunction(finfo);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceCallAggFunction
 *
 * This hook is invoked when an aggregate function is invoked
 * in the given query. pgaceCallFunction() is also invoked for
 * its transate function and finalize function.
 *
 * arguments:
 * - aggTuple is the tuple of target aggregate function stored
 *   in pg_aggregate system catalog.
 */
static inline void
pgaceCallAggFunction(HeapTuple aggTuple)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlCallAggFunction(aggTuple);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceCallFunctionTrigger
 *
 * This hook is invoked just before executing trigger function.
 * If it returns false, the trigger function is not invoked and
 * caller receives a NULL tuple as a result.
 * (It also means skip to update/delete the tuple in BR-triggers.)
 */
static inline bool
pgaceCallTriggerFunction(TriggerData *tgdata)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlCallTriggerFunction(tgdata);
		break;
#endif
	default:
		break;
	}
	return true;
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
static inline void
pgaceBeginPerformCheckFK(Relation rel, bool is_primary, Oid save_userid,
						 Datum *rowacl_private, Datum *pgace_private)
{
	/* A wired DAC state change */
	*rowacl_private = rowaclBeginPerformCheckFK(rel, is_primary, save_userid);

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			*pgace_private = sepgsqlBeginPerformCheckFK(rel, is_primary, save_userid);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceEndPerformCheckFK
 *
 * This hook is invoked just after performing FK constraint checks.
 * The guest can restore its internal state using this hook.
 */
static inline void
pgaceEndPerformCheckFK(Relation rel, Datum rowacl_private, Datum pgace_private)
{
	/* A wired DAC state restore */
	rowaclEndPerformCheckFK(rel, rowacl_private);

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlEndPerformCheckFK(rel, pgace_private);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceAllowInlineFunction
 *
 * This hook gives guest a chance to make decision just before
 * a set-returning function is inlined.
 *
 * arguments:
 * - fnoid is oid of the function to be inlined.
 * - func_tuple is tuple of the function stored in pg_proc.
 */
static inline bool
pgaceAllowFunctionInlined(Oid fnoid, HeapTuple func_tuple)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlAllowFunctionInlined(fnoid, func_tuple);
		break;
#endif
	default:
		break;
	}
	return true;
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLockTable(relid);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlCopyTable(rel, attNumList, isFrom);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlCopyFile(rel, fdesc, filename, isFrom);
		break;
#endif
	default:
		break;
	}
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
	/* A wired DAC check */
	if (!rowaclCopyToTuple(rel, attNumList, tuple))
		return false;

	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlCopyToTuple(rel, attNumList, tuple);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLoadSharedModule(filename);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLargeObjectCreate(rel, tuple);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLargeObjectDrop(rel, tuple, pgaceItem);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLargeObjectRead(lodesc, length);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceLargeObjectWrite
 *
 * This hook is invoked at the head of lo_write().
 */
static inline void
pgaceLargeObjectWrite(LargeObjectDesc *lodesc, int length)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLargeObjectWrite(lodesc, length);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceLargeObjectTruncate
 *
 * This hook is invoked at the head of lo_truncate().
 */
static inline void
pgaceLargeObjectTruncate(LargeObjectDesc *lodesc, int offset)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLargeObjectTruncate(lodesc, offset);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceLargeObjectImport
 *
 * This hook is invoked just before importing the given file.
 */
static inline void
pgaceLargeObjectImport(Oid loid, int fdesc, const char *filename)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLargeObjectImport(loid, fdesc, filename);
		break;
#endif
	default:
		break;
	}
}

/*
 * pgaceLargeObjectExport
 *
 * This hook is invoked just before exporting the given large object.
 */
static inline void
pgaceLargeObjectExport(Oid loid, int fdesc, const char *filename)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			sepgsqlLargeObjectExport(loid, fdesc, filename);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlLargeObjectGetSecurity(rel, tuple);
			return;
		}
		break;
#endif
	default:
		break;
	}
	ereport(ERROR,
			(errcode(ERRCODE_PGACE_ERROR),
			 errmsg("no enhanced security feature is available.")));
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
		{
			sepgsqlLargeObjectSetSecurity(rel, newtup, oldtup);
			return;
		}
		break;
#endif
	default:
		break;
	}
	ereport(ERROR,
			(errcode(ERRCODE_PGACE_ERROR),
			 errmsg("no enhanced security feature is available.")));
}

/******************************************************************
 * Security Label hooks
 ******************************************************************/

/*
 * pgaceTupleDescHasRowAcl
 *
 * This hook enables to control the value of TupleDesc->tdhasrowacl.
 * 
 */
static inline bool
pgaceTupleDescHasRowAcl(Relation rel, List *relopts)
{
	return rowaclTupleDescHasRowAcl(rel, relopts);
}

/*
 * pgaceTupleDescHasSecurity
 *
 * This hook enables to control the value in TupleDesc->tdhasseclabel.
 * If it returns true, sizeof(Oid) bytes are allocated at the header
 * of HeapTupleHeader structure.
 *
 * The 'rel' argument can be NULL, when we make a decision for newly
 * created relation via SELECT INTO/CREATE TABLE AS. In this case,
 * unparsed relation options are delivered.
 */
static inline bool
pgaceTupleDescHasSecLabel(Relation rel, List *relopts)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlTupleDescHasSecLabel(rel, relopts);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlTranslateSecurityLabelIn(seclabel);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlTranslateSecurityLabelOut(seclabel);
		break;
#endif
	default:
		break;
	}
	return seclabel;
}

/*
 * pgaceValidateSecurityLabel
 *
 * This hook enables the guest to validate the given security attribute
 * in raw-internal format.
 */
static inline bool
pgaceCheckValidSecurityLabel(char *seclabel)
{
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlCheckValidSecurityLabel(seclabel);
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlUnlabeledSecurityLabel();
		break;
#endif
	default:
		break;
	}
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
	switch (pgace_feature)
	{
#ifdef HAVE_SELINUX
	case PGACE_FEATURE_SELINUX:
		if (sepgsqlIsEnabled())
			return sepgsqlSecurityLabelOfLabel();
		break;
#endif
	default:
		break;
	}
	return NULL;
}

/******************************************************************
 * PGACE common facilities (not a hooks)
 ******************************************************************/

/* Security Label Management */
extern void pgacePostBootstrapingMode(void);

extern Oid pgaceLookupSecurityId(char *label);

extern char *pgaceLookupSecurityLabel(Oid sid);

extern Oid pgaceSecurityLabelToSid(char *label);

extern char *pgaceSidToSecurityLabel(Oid sid);


/* Extended SQL statements related */
extern List *pgaceRelationAttrList(CreateStmt *stmt);

extern void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple,
									  List *pgaceAttrList);
extern void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple,
									   List *pgaceAttrList);
extern void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd);

/* Export security system columns */
extern Datum pgaceHeapGetSecurityLabelSysattr(HeapTuple tuple);

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

/*
 * Row-level Database ACLs SQL FUNCTIONS
 */
extern Datum rowacl_grant(PG_FUNCTION_ARGS);
extern Datum rowacl_revoke(PG_FUNCTION_ARGS);
extern Datum rowacl_revoke_cascade(PG_FUNCTION_ARGS);
extern Datum rowacl_table_default(PG_FUNCTION_ARGS);


#endif // PGACE_H
