#ifndef SEPGSQL_INTERNAL_H
#define SEPGSQL_INTERNAL_H

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

typedef struct SEvalItem {
	NodeTag type;
	uint16 tclass;
	uint32 perms;
	union {
		struct {
			Oid relid;
			bool inh;
		} c;  /* for pg_class */
		struct {
			Oid relid;
			bool inh;
			AttrNumber attno;
		} a;  /* for pg_attribute */
		struct {
			Oid funcid;
		} p;  /* for pg_proc */
	};
} SEvalItem;
#define T_SEvalItem		(T_TIDBitmap + 1)		/* must be unique identifier */

/* object classes and access vectors are not included, in default */
#define SECCLASS_DATABASE			(61)	/* next to SECCLASS_DCCP_SOCKET */
#define SECCLASS_TABLE				(SECCLASS_DATABASE + 1)
#define SECCLASS_PROCEDURE			(SECCLASS_DATABASE + 2)
#define SECCLASS_COLUMN				(SECCLASS_DATABASE + 3)
#define SECCLASS_TUPLE				(SECCLASS_DATABASE + 4)
#define SECCLASS_BLOB				(SECCLASS_DATABASE + 5)

#define COMMON_DATABASE__CREATE                   0x00000001UL
#define COMMON_DATABASE__DROP                     0x00000002UL
#define COMMON_DATABASE__GETATTR                  0x00000004UL
#define COMMON_DATABASE__SETATTR                  0x00000008UL
#define COMMON_DATABASE__RELABELFROM              0x00000010UL
#define COMMON_DATABASE__RELABELTO                0x00000020UL

#define DATABASE__CREATE                          0x00000001UL
#define DATABASE__DROP                            0x00000002UL
#define DATABASE__GETATTR                         0x00000004UL
#define DATABASE__SETATTR                         0x00000008UL
#define DATABASE__RELABELFROM                     0x00000010UL
#define DATABASE__RELABELTO                       0x00000020UL
#define DATABASE__ACCESS                          0x00000040UL
#define DATABASE__INSTALL_MODULE                  0x00000080UL
#define DATABASE__LOAD_MODULE                     0x00000100UL
#define DATABASE__GET_PARAM                       0x00000200UL
#define DATABASE__SET_PARAM                       0x00000400UL
#define TABLE__CREATE                             0x00000001UL
#define TABLE__DROP                               0x00000002UL
#define TABLE__GETATTR                            0x00000004UL
#define TABLE__SETATTR                            0x00000008UL
#define TABLE__RELABELFROM                        0x00000010UL
#define TABLE__RELABELTO                          0x00000020UL
#define TABLE__SELECT                             0x00000040UL
#define TABLE__UPDATE                             0x00000080UL
#define TABLE__INSERT                             0x00000100UL
#define TABLE__DELETE                             0x00000200UL
#define TABLE__LOCK                               0x00000400UL
#define PROCEDURE__CREATE                         0x00000001UL
#define PROCEDURE__DROP                           0x00000002UL
#define PROCEDURE__GETATTR                        0x00000004UL
#define PROCEDURE__SETATTR                        0x00000008UL
#define PROCEDURE__RELABELFROM                    0x00000010UL
#define PROCEDURE__RELABELTO                      0x00000020UL
#define PROCEDURE__EXECUTE                        0x00000040UL
#define PROCEDURE__ENTRYPOINT                     0x00000080UL
#define COLUMN__CREATE                            0x00000001UL
#define COLUMN__DROP                              0x00000002UL
#define COLUMN__GETATTR                           0x00000004UL
#define COLUMN__SETATTR                           0x00000008UL
#define COLUMN__RELABELFROM                       0x00000010UL
#define COLUMN__RELABELTO                         0x00000020UL
#define COLUMN__SELECT                            0x00000040UL
#define COLUMN__UPDATE                            0x00000080UL
#define COLUMN__INSERT                            0x00000100UL
#define TUPLE__RELABELFROM                        0x00000001UL
#define TUPLE__RELABELTO                          0x00000002UL
#define TUPLE__SELECT                             0x00000004UL
#define TUPLE__UPDATE                             0x00000008UL
#define TUPLE__INSERT                             0x00000010UL
#define TUPLE__DELETE                             0x00000020UL
#define BLOB__CREATE                              0x00000001UL
#define BLOB__DROP                                0x00000002UL
#define BLOB__GETATTR                             0x00000004UL
#define BLOB__SETATTR                             0x00000008UL
#define BLOB__RELABELFROM                         0x00000010UL
#define BLOB__RELABELTO                           0x00000020UL
#define BLOB__READ                                0x00000040UL
#define BLOB__WRITE                               0x00000080UL
#define BLOB__IMPORT                              0x00000100UL
#define BLOB__EXPORT                              0x00000200UL
#define TUPLE__PERMS_MASK           ((TUPLE__DELETE << 1) - 1)

/*
 * SE-PostgreSQL core functions
 *   src/backend/security/sepgsqlCore.c
 */
extern bool  sepgsqlIsEnabled(void);
extern Size  sepgsqlShmemSize(void);
extern void  sepgsqlInitialize(void);
extern int   sepgsqlInitializePostmaster(void);
extern void  sepgsqlFinalizePostmaster(void);

extern Oid  sepgsqlGetServerContext(void);
extern Oid  sepgsqlGetClientContext(void);
extern void  sepgsqlSetClientContext(Oid new_ctx);
extern Oid  sepgsqlGetDatabaseContext(void);
extern char *sepgsqlGetDatabaseName(void);

extern bool sepgsql_avc_permission_noaudit(Oid ssid, Oid tsid, uint16 tclass,
										   uint32 perms, char **audit, char *objname);
extern void  sepgsql_avc_permission(Oid ssid, Oid tsid, uint16 tclass,
									uint32 perms, char *objname);
extern void  sepgsql_audit(bool result, char *message);
extern Oid   sepgsql_avc_createcon(Oid ssid, Oid tsid, uint16 tclass);
extern Oid   sepgsql_avc_relabelcon(Oid ssid, Oid tsid, uint16 tclass);
extern bool  sepgsql_check_context(char *context);

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);

/*
 * SE-PostgreSQL proxy functions
 *   src/backend/security/sepgsqlProxy.c
 */
extern List *sepgsqlProxyQuery(Query *query);
extern List *sepgsqlProxyQueryList(List *queryList);
extern Oid sepgsqlPreparePlanCheck(Relation rel);
extern void sepgsqlRestorePlanCheck(Relation rel, Oid pgace_saved);

/*
 * SE-PostgreSQL checking function
 *   src/backend/security/sepgsqlVerify.c
 */
//extern void sepgsqlVerifyQueryList(List *queryList);
extern void sepgsqlVerifyQuery(Query *query);

/*
 * SE-PostgreSQL hooks
 *   src/backend/security/sepgsqlHooks.c
 */

/* simple_heap_xxxx hooks */
extern void sepgsqlSimpleHeapInsert(Relation rel, HeapTuple tuple);
extern void sepgsqlSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple newtup);
extern void sepgsqlSimpleHeapDelete(Relation rel, ItemPointer tid);

/* heap_xxxx hooks for implicit labeling */
extern void sepgsqlHeapInsert(Relation rel, HeapTuple tuple);
extern void sepgsqlHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup);

/* INSERT/UPDATE/DELETE statement hooks */
extern bool sepgsqlExecInsert(Relation rel, HeapTuple tuple, bool with_returning);
extern bool sepgsqlExecUpdate(Relation rel, HeapTuple newtup, ItemPointer tid, bool with_returning);
extern bool sepgsqlExecDelete(Relation rel, ItemPointer tid, bool with_returning);

/* DATABASE */
extern void sepgsqlAlterDatabaseContext(Relation rel, HeapTuple tuple, char *new_context);
extern void sepgsqlSetDatabaseParam(const char *name, char *argstring);
extern void sepgsqlGetDatabaseParam(const char *name);

/* RELATION/ATTRIBUTE */
extern void sepgsqlLockTable(Oid relid);

/* FUNCTION */
extern void sepgsqlCallFunction(FmgrInfo *finfo, bool with_perm_check);
extern void sepgsqlAlterProcedureContext(Relation rel, HeapTuple tuple, char *context);

/* COPY */
extern void sepgsqlCopyTable(Relation rel, List *attnumlist, bool is_from);
extern bool sepgsqlCopyTuple(Relation rel, HeapTuple tuple);

/* LOAD shared library module */
extern void sepgsqlLoadSharedModule(const char *filename);

/* copy/print node object */
extern Node *sepgsqlCopyObject(Node *node);
extern bool sepgsqlOutObject(StringInfo str, Node *node);

/* SECURITY LABEL IN/OUT */
extern char *sepgsqlSecurityLabelIn(char *context);
extern char *sepgsqlSecurityLabelOut(char *context);
extern bool sepgsqlSecurityLabelIsValid(char *context);
extern char *sepgsqlSecurityLabelOfLabel(char *context);

/*
 * SE-PostgreSQL Binary Large Object (BLOB) functions
 *   src/backend/security/sepgsqlLargeObject.c
 */
extern Oid  sepgsqlLargeObjectGetSecurity(HeapTuple tuple);
extern void sepgsqlLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security, bool is_first);
extern void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only);
extern void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup);
extern void sepgsqlLargeObjectImport(void);
extern void sepgsqlLargeObjectExport(void);

/*
 * SE-PostgreSQL Heap related functions
 *   src/backend/security/sepgsqlHeap.c
 */

extern Oid sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple);
extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple oldtup,
								   uint32 perms, bool abort);
extern Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

/*
 * SE-PostgreSQL extended SQL statement
 *   src/backend/security/sepgsqlExtStmt.c
 */
extern DefElem *sepgsqlGramSecurityLabel(char *defname, char *context);

extern bool sepgsqlAlterTablePrepare(Relation rel, AlterTableCmd *cmd);
extern bool sepgsqlAlterTable(Relation rel, AlterTableCmd *cmd);
extern void pgsqlAlterFunction(Relation rel, HeapTuple tuple, char *context);
extern void pgsqlAlterDatabase(Relation rel, HeapTuple tuple, char *context);

#endif /* SEPGSQL_INTERNAL_H */
