/*
 * src/include/security/sepgsql.h
 *    headers for Security-Enhanced PostgreSQL (SE-PostgreSQL)
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

/* system catalogs */
#include "catalog/pg_security.h"
#include "lib/stringinfo.h"
#include "nodes/execnodes.h"
#include "nodes/nodes.h"
#include "nodes/params.h"
#include "nodes/parsenodes.h"

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

/*
 * SE-PostgreSQL modes
 */
typedef enum
{
	SEPGSQL_MODE_DEFAULT,
	SEPGSQL_MODE_ENFORCING,
	SEPGSQL_MODE_PERMISSIVE,
	SEPGSQL_MODE_DISABLED,
} SepgsqlModeType;

extern int sepostgresql_mode;

/*
 * Permission codes of internal representation
 */
#define SEPGSQL_PERMS_USE				(1UL << 0)
#define SEPGSQL_PERMS_SELECT			(1UL << 1)
#define SEPGSQL_PERMS_UPDATE			(1UL << 2)
#define SEPGSQL_PERMS_INSERT			(1UL << 3)
#define SEPGSQL_PERMS_DELETE			(1UL << 4)
#define SEPGSQL_PERMS_RELABELFROM		(1UL << 5)
#define SEPGSQL_PERMS_RELABELTO			(1UL << 6)
#define SEPGSQL_PERMS_READ				(1UL << 7)
#define SEPGSQL_PERMS_WRITE				(1UL << 8)

/*
 * The implementation of PGACE/SE-PostgreSQL hooks
 */

/* Initialize / Finalize related hooks */
extern Size sepgsqlShmemSize(void);

extern void sepgsqlInitialize(bool is_bootstrap);

extern pid_t sepgsqlStartupWorkerProcess(void);

/* SQL proxy hooks */
extern List *sepgsqlProxyQuery(List *queryList);

extern void sepgsqlVerifyQuery(PlannedStmt *pstmt, int eflags);

extern void sepgsqlEvaluateParams(List *params);

extern void sepgsqlProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel);

/* ExecScan hooks */
extern bool sepgsqlExecScan(Scan *scan, Relation rel, TupleTableSlot *slot);

/* HeapTuple modification hooks */
extern bool sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
								   bool is_internal, bool with_returning);
extern bool sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid,
								   HeapTuple newtup, bool is_internal,
								   bool with_returning);
extern bool sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid,
								   bool is_internal, bool with_returning);

/*	Extended SQL statement hooks */
extern DefElem *sepgsqlGramSecurityItem(char *defname, char *value);

extern bool sepgsqlIsGramSecurityItem(DefElem *defel);

extern void sepgsqlGramCreateRelation(Relation rel, HeapTuple tuple,
									  DefElem *defel);
extern void sepgsqlGramCreateAttribute(Relation rel, HeapTuple tuple,
									   DefElem *defel);
extern void sepgsqlGramAlterRelation(Relation rel, HeapTuple tuple,
									 DefElem *defel);
extern void sepgsqlGramAlterAttribute(Relation rel, HeapTuple tuple,
									  DefElem *defel);
extern void sepgsqlGramCreateDatabase(Relation rel, HeapTuple tuple,
									  DefElem *defel);
extern void sepgsqlGramAlterDatabase(Relation rel, HeapTuple tuple,
									 DefElem *defel);
extern void sepgsqlGramCreateFunction(Relation rel, HeapTuple tuple,
									  DefElem *defel);
extern void sepgsqlGramAlterFunction(Relation rel, HeapTuple tuple,
									 DefElem *defel);

/* DATABASE related hooks */
extern void sepgsqlSetDatabaseParam(const char *name, char *argstring);

extern void sepgsqlGetDatabaseParam(const char *name);

/* FUNCTION related hooks */
extern void sepgsqlCallFunction(FmgrInfo *finfo, bool with_perm_check);

extern bool sepgsqlCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata);

extern void sepgsqlBeginPerformCheckFK(Relation rel, bool rel_is_primary, Datum *save_pgace);

extern void sepgsqlEndPerformCheckFK(Relation rel, bool rel_is_primary, Datum save_pgace);

/* TABLE related hooks */
extern void sepgsqlLockTable(Oid relid);

extern bool sepgsqlAlterTable(Relation rel, AlterTableCmd *cmd);

/* COPY TO/COPY FROM statement hooks */
extern void sepgsqlCopyTable(Relation rel, List *attnumlist, bool is_from);

extern void sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom);

extern bool sepgsqlCopyToTuple(Relation rel, List *attnumlist, HeapTuple tuple);

/* Loadable shared library module hooks */
extern void sepgsqlLoadSharedModule(const char *filename);

/* Binary Large Object (BLOB) hooks */
extern void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple);

extern void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple, void **pgaceItem);

extern void sepgsqlLargeObjectRead(LargeObjectDesc *lodesc, int length);

extern void sepgsqlLargeObjectWrite(LargeObjectDesc *lodesc, int length);

extern void sepgsqlLargeObjectTruncate(LargeObjectDesc *lodesc, int offset);

extern void sepgsqlLargeObjectImport(Oid loid, int fdesc, const char *filename);

extern void sepgsqlLargeObjectExport(Oid loid, int fdesc, const char *filename);

extern void sepgsqlLargeObjectGetSecurity(Relation rel, HeapTuple tuple);

extern void sepgsqlLargeObjectSetSecurity(Relation rel, HeapTuple newtup, HeapTuple oldtup);

/* Security Label hooks */
extern char *sepgsqlTranslateSecurityLabelIn(const char *context);

extern char *sepgsqlTranslateSecurityLabelOut(const char *context);

extern bool  sepgsqlCheckValidSecurityLabel(char *context);

extern char *sepgsqlUnlabeledSecurityLabel(void);

extern char *sepgsqlSecurityLabelOfLabel(void);

/*
 * SE-PostgreSQL core functions
 *	 src/backend/security/sepgsql/core.c
 */
extern bool sepgsqlIsEnabled(void);

extern const security_context_t sepgsqlGetServerContext(void);

extern const security_context_t sepgsqlGetClientContext(void);

extern const security_context_t sepgsqlGetDatabaseContext(void);

extern const security_context_t sepgsqlGetUnlabeledContext(void);

extern const security_context_t sepgsqlSwitchClientContext(security_context_t newcon);

extern Oid sepgsqlGetDatabaseSecurityId(void);

/*
 * SE-PostgreSQL userspace avc functions
 *   src/backend/security/sepgsql/avc.c
 */
extern void sepgsqlAvcInit(void);

extern void sepgsqlAvcSwitchClientContext(security_context_t context);

extern void sepgsqlClientHasPermission(Oid target_security_id,
									   security_class_t tclass,
									   access_vector_t perms,
									   const char *objname);

extern bool sepgsqlClientHasPermissionNoAbort(Oid target_security_id,
											  security_class_t tclass,
											  access_vector_t perms,
											  const char *objname);

extern Oid sepgsqlClientCreateSid(Oid target_security_id,
								  security_class_t tclass);

extern security_context_t
sepgsqlClientCreateContext(Oid target_security_id,
						   security_class_t tclass);

extern bool sepgsqlComputePermission(const security_context_t scontext,
									 const security_context_t tcontext,
									 security_class_t tclass,
									 access_vector_t perms,
									 const char *objname);

extern security_context_t
sepgsqlComputeCreateContext(const security_context_t scontext,
							const security_context_t tcontext,
							security_class_t tclass);

/*
 * SE-PostgreSQL permission evaluation related
 *	 src/backend/security/sepgsql/permission.c
 */
extern const char *sepgsqlTupleName(Oid relid, HeapTuple tuple);

extern void sepgsqlSetDefaultContext(Relation rel, HeapTuple tuple);

extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple,
								   HeapTuple oldtup, uint32 perms, bool abort);
#endif   /* SEPGSQL_H */
