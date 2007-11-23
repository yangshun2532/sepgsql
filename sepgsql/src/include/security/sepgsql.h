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

/* object classes and access vectors are not included, in default */
#ifndef SECCLASS_DB_DATABASE
#define SECCLASS_DB_DATABASE		(62)	/* next to SECCLASS_MEMPROTECT */
#endif
#define SECCLASS_DB_TABLE			(SECCLASS_DB_DATABASE + 1)
#define SECCLASS_DB_PROCEDURE		(SECCLASS_DB_DATABASE + 2)
#define SECCLASS_DB_COLUMN			(SECCLASS_DB_DATABASE + 3)
#define SECCLASS_DB_TUPLE			(SECCLASS_DB_DATABASE + 4)
#define SECCLASS_DB_BLOB			(SECCLASS_DB_DATABASE + 5)

#define COMMON_DATABASE__CREATE                   0x00000001UL
#define COMMON_DATABASE__DROP                     0x00000002UL
#define COMMON_DATABASE__GETATTR                  0x00000004UL
#define COMMON_DATABASE__SETATTR                  0x00000008UL
#define COMMON_DATABASE__RELABELFROM              0x00000010UL
#define COMMON_DATABASE__RELABELTO                0x00000020UL

#define DB_DATABASE__CREATE                       0x00000001UL
#define DB_DATABASE__DROP                         0x00000002UL
#define DB_DATABASE__GETATTR                      0x00000004UL
#define DB_DATABASE__SETATTR                      0x00000008UL
#define DB_DATABASE__RELABELFROM                  0x00000010UL
#define DB_DATABASE__RELABELTO                    0x00000020UL
#define DB_DATABASE__ACCESS                       0x00000040UL
#define DB_DATABASE__INSTALL_MODULE               0x00000080UL
#define DB_DATABASE__LOAD_MODULE                  0x00000100UL
#define DB_DATABASE__GET_PARAM                    0x00000200UL
#define DB_DATABASE__SET_PARAM                    0x00000400UL
#define DB_TABLE__CREATE                          0x00000001UL
#define DB_TABLE__DROP                            0x00000002UL
#define DB_TABLE__GETATTR                         0x00000004UL
#define DB_TABLE__SETATTR                         0x00000008UL
#define DB_TABLE__RELABELFROM                     0x00000010UL
#define DB_TABLE__RELABELTO                       0x00000020UL
#define DB_TABLE__USE                             0x00000040UL
#define DB_TABLE__SELECT                          0x00000080UL
#define DB_TABLE__UPDATE                          0x00000100UL
#define DB_TABLE__INSERT                          0x00000200UL
#define DB_TABLE__DELETE                          0x00000400UL
#define DB_TABLE__LOCK                            0x00000800UL
#define DB_PROCEDURE__CREATE                      0x00000001UL
#define DB_PROCEDURE__DROP                        0x00000002UL
#define DB_PROCEDURE__GETATTR                     0x00000004UL
#define DB_PROCEDURE__SETATTR                     0x00000008UL
#define DB_PROCEDURE__RELABELFROM                 0x00000010UL
#define DB_PROCEDURE__RELABELTO                   0x00000020UL
#define DB_PROCEDURE__EXECUTE                     0x00000040UL
#define DB_PROCEDURE__ENTRYPOINT                  0x00000080UL
#define DB_COLUMN__CREATE                         0x00000001UL
#define DB_COLUMN__DROP                           0x00000002UL
#define DB_COLUMN__GETATTR                        0x00000004UL
#define DB_COLUMN__SETATTR                        0x00000008UL
#define DB_COLUMN__RELABELFROM                    0x00000010UL
#define DB_COLUMN__RELABELTO                      0x00000020UL
#define DB_COLUMN__USE                            0x00000040UL
#define DB_COLUMN__SELECT                         0x00000080UL
#define DB_COLUMN__UPDATE                         0x00000100UL
#define DB_COLUMN__INSERT                         0x00000200UL
#define DB_TUPLE__RELABELFROM                     0x00000001UL
#define DB_TUPLE__RELABELTO                       0x00000002UL
#define DB_TUPLE__USE                             0x00000004UL
#define DB_TUPLE__SELECT                          0x00000008UL
#define DB_TUPLE__UPDATE                          0x00000010UL
#define DB_TUPLE__INSERT                          0x00000020UL
#define DB_TUPLE__DELETE                          0x00000040UL
#define DB_BLOB__CREATE                           0x00000001UL
#define DB_BLOB__DROP                             0x00000002UL
#define DB_BLOB__GETATTR                          0x00000004UL
#define DB_BLOB__SETATTR                          0x00000008UL
#define DB_BLOB__RELABELFROM                      0x00000010UL
#define DB_BLOB__RELABELTO                        0x00000020UL
#define DB_BLOB__READ                             0x00000040UL
#define DB_BLOB__WRITE                            0x00000080UL
#define DB_BLOB__IMPORT                           0x00000100UL
#define DB_BLOB__EXPORT                           0x00000200UL

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
extern void  sepgsqlVerifyQuery(Query *query);

/* HeapTuple modification hooks */
extern bool  sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
									bool is_internal, bool with_returning);
extern bool  sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
								   bool is_internal, bool with_returning);
extern bool  sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid,
								   bool is_internal, bool with_returning);

/*  Extended SQL statement hooks */
extern DefElem *sepgsqlGramSecurityItem(const char *defname, const char *value);
extern bool pgaceIsGramSecurityItem(DefElem *defel);
extern void pgaceGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel);

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
extern bool  sepgsql_avc_permission_noaudit(Oid ssid, Oid tsid, uint16 tclass,
											uint32 perms, char **audit, char *objname);
extern void  sepgsql_audit(bool result, char *message);
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
