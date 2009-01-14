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
#include "commands/trigger.h"
#include "executor/execdesc.h"
#include "fmgr.h"
#include "nodes/params.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "storage/large_object.h"
#include "utils/rel.h"

#include "security/rowacl.h"
#ifdef HAVE_SELINUX
#include "security/sepgsql.h"
#endif

/*
 * pgace_feature : GUC parameter to choose an enhanced security feature
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
 * Initialization hooks
 */
extern Size pgaceShmemSize(void);
extern void pgaceInitialize(bool is_bootstrap);
extern pid_t pgaceStartupWorkerProcess(void);

/*
 * SQL proxy hooks
 */
extern List *pgaceProxyQuery(List *queryList);
extern void pgaceExecutorStart(QueryDesc *queryDesc, int eflags);
extern void pgaceProcessUtility(Node *parsetree, ParamListInfo params,
								bool isTopLevel);
/*
 * HeapTuple input/output hooks
 */
extern bool pgaceExecScan(Scan *scan, Relation rel, TupleTableSlot *slot);
extern bool pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
								 bool is_internal, bool with_returning);
extern bool pgaceHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
								 bool is_internal, bool with_returning);
extern bool pgaceHeapTupleDelete(Relation rel, ItemPointer otid,
								 bool is_internal, bool with_returning);
/*
 * Enhanced SQL statements
 */
extern bool pgaceIsGramSecurityItem(DefElem *defel);
extern void pgaceGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel);

/*
 * Function related hooks
 */
extern void pgaceCallFunction(FmgrInfo *finfo);
extern void pgaceCallAggFunction(HeapTuple aggTuple);
extern bool pgaceCallTriggerFunction(TriggerData *tgdata);
extern void pgaceBeginPerformCheckFK(Relation rel, bool is_primary, Oid save_userid,
									 Datum *rowacl_private, Datum *pgace_private);
extern void pgaceEndPerformCheckFK(Relation rel,
								   Datum rowacl_private, Datum pgace_private);
extern bool pgaceAllowFunctionInlined(Oid fnoid, HeapTuple func_tuple);

/*
 * Misc hooks
 */
extern void pgaceSetDatabaseParam(const char *name, char *argstring);
extern void pgaceGetDatabaseParam(const char *name);
extern void pgaceLockTable(Oid relid);

/*
 * COPY TO/FROM statement hooks
 */
extern void pgaceCopyTable(Relation rel, List *attNumList, bool isFrom);
extern void pgaceCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom);
extern bool pgaceCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple);

/*
 * Loadable shared library module hooks
 */
extern void pgaceLoadSharedModule(const char *filename);

/*
 * Binary Large Object hooks
 */
extern void pgaceLargeObjectCreate(Relation rel, HeapTuple tuple);
extern void pgaceLargeObjectDrop(Relation rel, HeapTuple tuple, void **pgaceItem);
extern void pgaceLargeObjectRead(LargeObjectDesc *lodesc, int length);
extern void pgaceLargeObjectWrite(LargeObjectDesc *lodesc, int length);
extern void pgaceLargeObjectTruncate(LargeObjectDesc *lodesc, int offset);
extern void pgaceLargeObjectImport(Oid loid, int fdesc, const char *filename);
extern void pgaceLargeObjectExport(Oid loid, int fdesc, const char *filename);
extern void pgaceLargeObjectGetSecurity(Relation rel, HeapTuple tuple);
extern void pgaceLargeObjectSetSecurity(Relation rel,
										HeapTuple newtup, HeapTuple oldtup);
/*
 * Security Label hooks
 */
extern bool pgaceTupleDescHasRowAcl(Relation rel, List *relopts);
extern bool pgaceTupleDescHasSecLabel(Relation rel, List *relopts);
extern char *pgaceTranslateSecurityLabelIn(char *seclabel);
extern char *pgaceTranslateSecurityLabelOut(char *seclabel);
extern bool pgaceCheckValidSecurityLabel(char *seclabel);
extern char *pgaceUnlabeledSecurityLabel(void);
extern char *pgaceSecurityLabelOfLabel(void);

/*
 * PGACE common facilities (not hooks)
 */

/* security label management */
extern void pgacePostBootstrapingMode(void);

extern Oid pgaceLookupSecurityId(char *label);

extern char *pgaceLookupSecurityLabel(Oid sid);

extern Oid pgaceSecurityLabelToSid(char *label);

extern char *pgaceSidToSecurityLabel(Oid sid);

/* Enhanced SQL statements related */
extern List *pgaceRelationAttrList(CreateStmt *stmt);

extern void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple,
									  List *pgaceAttrList);
extern void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple,
									   List *pgaceAttrList);
extern void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd);

/* Export security system columns */
extern Datum pgaceHeapGetSecurityLabelSysattr(HeapTuple tuple);

/*
 * SQL functions
 */

/* SE-PostgreSQL */
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

/* Row-level ACLs */
extern Datum rowacl_grant(PG_FUNCTION_ARGS);
extern Datum rowacl_revoke(PG_FUNCTION_ARGS);
extern Datum rowacl_revoke_cascade(PG_FUNCTION_ARGS);

#endif // PGACE_H
