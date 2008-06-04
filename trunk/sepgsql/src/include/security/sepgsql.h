#ifndef SEPGSQL_H
#define SEPGSQL_H

/* system catalogs */
#include "catalog/pg_security.h"
#include "lib/stringinfo.h"
#include "nodes/execnodes.h"
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
extern List *sepgsqlProxyQuery(Query *query);

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

extern Datum sepgsqlPreparePlanCheck(Relation rel);

extern void sepgsqlRestorePlanCheck(Relation rel, Datum pgace_saved);

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
extern void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple);

extern void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple,
								   bool is_first, Datum *pgaceItem);

extern bool sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple,
								   bool is_first, Datum *pgaceItem);

extern void sepgsqlLargeObjectWrite(Relation rel, Relation idx,
									HeapTuple newtup, HeapTuple oldtup,
									bool is_first, Datum *pgaceItem);

extern void sepgsqlLargeObjectImport(Oid loid, int fdesc, const char *filename);

extern void sepgsqlLargeObjectExport(Oid loid, int fdesc, const char *filename);

extern void sepgsqlLargeObjectGetSecurity(Relation rel, HeapTuple tuple);

extern void sepgsqlLargeObjectSetSecurity(Relation rel, HeapTuple tuple, Oid security_id,
										  bool is_first, Datum *pgaceItem);

/* Security Label hooks */
extern char *sepgsqlTranslateSecurityLabelIn(char *context);

extern char *sepgsqlTranslateSecurityLabelOut(char *context);

extern char *sepgsqlValidateSecurityLabel(char *context);

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

/*
 * SE-PostgreSQL userspace avc functions
 *   src/backend/security/sepgsql/avc.c
 */
extern void sepgsqlAvcInit(void);

extern void sepgsqlAvcPermission(const security_context_t scon,
								 const security_context_t tcon,
								 security_class_t tclass,
								 access_vector_t perms,
								 const char *objname);

extern bool sepgsqlAvcPermissionNoAbort(const security_context_t scon,
										const security_context_t tcon,
										security_class_t tclass,
										access_vector_t perms,
										const char *objname);

extern security_context_t sepgsqlAvcCreateCon(const security_context_t scon,
											  const security_context_t tcon,
											  security_class_t tclass);

/*
 * SE-PostgreSQL permission evaluation related
 *	 src/backend/security/sepgsql/permission.c
 */
extern bool sepgsqlGetTupleName(Oid relid, HeapTuple tuple, char *buffer, int buflen);

extern const char *sepgsqlTupleName(Oid relid, HeapTuple tuple);

extern security_context_t sepgsqlGetDefaultContext(Relation rel, HeapTuple tuple);

extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple,
								   HeapTuple oldtup, uint32 perms, bool abort);

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


#endif   /* SEPGSQL_H */
