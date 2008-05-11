#ifndef SEPGSQL_H
#define SEPGSQL_H

/* system catalogs */
#include "catalog/pg_security.h"
#include "lib/stringinfo.h"
#include "nodes/nodes.h"
#include "nodes/params.h"
#include "nodes/parsenodes.h"
#include "storage/large_object.h"

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

/*
 * Permission codes of internal representation
 */
#define SEPGSQL_PERMS_USE				(1UL << (N_ACL_RIGHTS + 0))
#define SEPGSQL_PERMS_SELECT			(1UL << (N_ACL_RIGHTS + 1))
#define SEPGSQL_PERMS_UPDATE			(1UL << (N_ACL_RIGHTS + 2))
#define SEPGSQL_PERMS_INSERT			(1UL << (N_ACL_RIGHTS + 3))
#define SEPGSQL_PERMS_DELETE			(1UL << (N_ACL_RIGHTS + 4))
#define SEPGSQL_PERMS_RELABELFROM		(1UL << (N_ACL_RIGHTS + 5))
#define SEPGSQL_PERMS_RELABELTO			(1UL << (N_ACL_RIGHTS + 6))
#define SEPGSQL_PERMS_READ				(1UL << (N_ACL_RIGHTS + 7))
#define SEPGSQL_PERMS_WRITE				(1UL << (N_ACL_RIGHTS + 8))
#define SEPGSQL_PERMS_ALL				((SEPGSQL_PERMS_WRITE << 1) - SEPGSQL_PERMS_USE)

/*
 * The implementation of PGACE/SE-PostgreSQL hooks
 */

/* Initialize / Finalize related hooks */
extern Size sepgsqlShmemSize(void);

extern void sepgsqlInitialize(bool is_bootstrap);

extern int	sepgsqlInitializePostmaster(void);

extern void sepgsqlFinalizePostmaster(void);

extern void sepgsqlBootstrapBuildSecurity(void);

/* SQL proxy hooks */
extern List *sepgsqlProxyQuery(Query *query);

extern void sepgsqlVerifyQuery(PlannedStmt *pstmt, int eflags);

extern void sepgsqlEvaluateParams(List *params);

extern void sepgsqlProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel);

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

extern Oid	sepgsqlPreparePlanCheck(Relation rel);

extern void sepgsqlRestorePlanCheck(Relation rel, Oid pgace_saved);

/* TABLE related hooks */
extern void sepgsqlLockTable(Oid relid);

extern bool sepgsqlAlterTable(Relation rel, AlterTableCmd *cmd);

/* COPY TO/COPY FROM statement hooks */
extern void sepgsqlCopyTable(Relation rel, List *attnumlist, bool is_from);

extern bool sepgsqlCopyToTuple(Relation rel, List *attnumlist,
							   HeapTuple tuple);

/* Loadable shared library module hooks */
extern void sepgsqlLoadSharedModule(const char *filename);

/* Binary Large Object (BLOB) hooks */
extern void sepgsqlLargeObjectGetSecurity(HeapTuple tuple);

extern void sepgsqlLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security);

extern void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple);

extern void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple);

extern void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple);

extern void sepgsqlLargeObjectWrite(Relation rel, HeapTuple newtup,
									HeapTuple oldtup);
extern void sepgsqlLargeObjectTruncate(Relation rel, Oid loid,
									   HeapTuple headtup);
extern void sepgsqlLargeObjectImport(void);

extern void sepgsqlLargeObjectExport(void);

/* Security Label hooks */
extern char *sepgsqlSecurityLabelIn(char *context);

extern char *sepgsqlSecurityLabelOut(char *context);

extern char *sepgsqlSecurityLabelCheckValid(char *context);

extern char *sepgsqlSecurityLabelOfLabel();

/*
 * SE-PostgreSQL core functions
 *	 src/backend/security/sepgsql/core.c
 */
extern bool sepgsqlIsEnabled(void);

extern Oid	sepgsqlGetServerContext(void);

extern Oid	sepgsqlGetClientContext(void);

extern void sepgsqlSetClientContext(Oid new_ctx);

extern Oid	sepgsqlGetDatabaseContext(void);

extern char *sepgsqlGetDatabaseName(void);

/* userspace access vector cache related */
extern void sepgsql_avc_permission(Oid ssid, Oid tsid, uint16 tclass,
								   uint32 perms, char *objname);
extern bool sepgsql_avc_permission_noabort(Oid ssid, Oid tsid, uint16 tclass,
										   uint32 perms, char *objname);
extern Oid	sepgsql_avc_createcon(Oid ssid, Oid tsid, uint16 tclass);

extern Oid	sepgsql_avc_relabelcon(Oid ssid, Oid tsid, uint16 tclass);

/*
 * SE-PostgreSQL permission evaluation related
 *	 src/backend/security/sepgsql/permission.c
 */
extern char *sepgsqlGetTupleName(Oid relid, HeapTuple tuple, NameData *name);

extern Oid	sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple);

extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple,
								   HeapTuple oldtup, uint32 perms, bool abort);

/*
 * SE-PostgreSQL SQL FUNCTIONS
 */
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);

extern Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);

extern Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

#endif   /* SEPGSQL_H */
