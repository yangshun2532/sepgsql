#ifndef SEPGSQL_H
#define SEPGSQL_H

/* system catalogs */
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_am.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_class.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_listener.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_pltemplate.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_security.h"
#include "catalog/pg_tablespace.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "lib/stringinfo.h"
#include "nodes/nodes.h"
#include "storage/large_object.h"

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

#define selerror(fmt, ...)												\
	ereport(ERROR,  (errcode(ERRCODE_INTERNAL_ERROR),					\
					 errmsg("%s(%d): " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)))
#define selnotice(fmt, ...)												\
	ereport(NOTICE, (errcode(ERRCODE_WARNING),							\
					 errmsg("%s(%d): " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)))
#define seldebug(fmt, ...)												\
	ereport(NOTICE, (errcode(ERRCODE_WARNING),							\
					 errmsg("%s(%d): " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)))
#define selbugon(x)	do { if (x)((char *)NULL)[0] = 'a'; }while(0)

/*
 * The implementation of PGACE/SE-PostgreSQL hooks
 */

/* Initialize / Finalize related hooks */
extern Size  sepgsqlShmemSize(void);
extern void  sepgsqlInitialize(bool is_bootstrap);
extern int   sepgsqlInitializePostmaster(void);
extern void  sepgsqlFinalizePostmaster(void);

/* SQL proxy hooks */
extern List *sepgsqlProxyQuery(Query *query);
extern void  sepgsqlVerifyQuery(PlannedStmt *pstmt);

/* HeapTuple modification hooks */
extern bool  sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
									bool is_internal, bool with_returning);
extern bool  sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
								   bool is_internal, bool with_returning);
extern bool  sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid,
								   bool is_internal, bool with_returning);

/*  Extended SQL statement hooks */
extern DefElem *sepgsqlGramSecurityItem(char *defname, char *value);
extern bool sepgsqlIsGramSecurityItem(DefElem *defel);
extern void sepgsqlGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void sepgsqlGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void sepgsqlGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void sepgsqlGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void sepgsqlGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void sepgsqlGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void sepgsqlGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel);
extern void sepgsqlGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel);

/* DATABASE related hooks */
extern void  sepgsqlSetDatabaseParam(const char *name, char *argstring);
extern void  sepgsqlGetDatabaseParam(const char *name);

/* FUNCTION related hooks */
extern void  sepgsqlCallFunction(FmgrInfo *finfo, bool with_perm_check);
extern bool  sepgsqlCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata);
extern Oid   sepgsqlPreparePlanCheck(Relation rel);
extern void  sepgsqlRestorePlanCheck(Relation rel, Oid pgace_saved);

/* TABLE related hooks */
extern void  sepgsqlLockTable(Oid relid);
extern bool  sepgsqlAlterTable(Relation rel, AlterTableCmd *cmd);

/* COPY TO/COPY FROM statement hooks */
extern void  sepgsqlCopyTable(Relation rel, List *attnumlist, bool is_from);
extern bool  sepgsqlCopyToTuple(Relation rel, HeapTuple tuple);

/* Loadable shared library module hooks */
extern void  sepgsqlLoadSharedModule(const char *filename);

/* Binary Large Object (BLOB) hooks */
extern Oid   sepgsqlLargeObjectGetSecurity(HeapTuple tuple);
extern void  sepgsqlLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first);
extern void  sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple);
extern void  sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple);
extern void  sepgsqlLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only);
extern void  sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple);
extern void  sepgsqlLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup);
extern void  sepgsqlLargeObjectTruncate(Relation rel, Oid loid);
extern void  sepgsqlLargeObjectImport(void);
extern void  sepgsqlLargeObjectExport(void);

/* Security Label hooks */
extern char *sepgsqlSecurityLabelIn(char *context);
extern char *sepgsqlSecurityLabelOut(char *context);
extern bool  sepgsqlSecurityLabelIsValid(char *context);
extern char *sepgsqlSecurityLabelOfLabel(char *context);
extern char *sepgsqlSecurityLabelNotFound(Oid sid);

/* Extended node type hooks */
extern Node *sepgsqlCopyObject(Node *node);
extern bool  sepgsqlOutObject(StringInfo str, Node *node);
extern void *sepgsqlReadObject(char *token);

/*
 * SE-PostgreSQL core functions
 *   src/backend/security/sepgsql/core.c
 */
extern bool  sepgsqlIsEnabled(void);
extern Oid   sepgsqlGetServerContext(void);
extern Oid   sepgsqlGetClientContext(void);
extern void  sepgsqlSetClientContext(Oid new_ctx);
extern Oid   sepgsqlGetDatabaseContext(void);
extern char *sepgsqlGetDatabaseName(void);

/* userspace access vector cache related */
extern void  sepgsql_avc_permission(Oid ssid, Oid tsid, uint16 tclass,
									uint32 perms, char *objname);
extern bool  sepgsql_avc_permission_noabort(Oid ssid, Oid tsid, uint16 tclass,
											uint32 perms, char *objname);
extern Oid   sepgsql_avc_createcon(Oid ssid, Oid tsid, uint16 tclass);
extern Oid   sepgsql_avc_relabelcon(Oid ssid, Oid tsid, uint16 tclass);

/*
 * SE-PostgreSQL permission evaluation related
 *   src/backend/security/sepgsql/permission.c
 */
extern char *sepgsqlGetTupleName(Oid relid, HeapTuple tuple);
extern Oid   sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple);
extern bool  sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple oldtup,
									uint32 perms, bool abort);
/*
 * SE-PostgreSQL SQL FUNCTIONS
 */
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

#endif /* SEPGSQL_H */
