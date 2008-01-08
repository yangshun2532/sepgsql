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

// for debugging macros
#define seldump_pg_class(rel)											\
	selnotice("pg_class (%p) { relname='%s', relnamespace=%u, reltype=%u, "	\
			  "relowner=%u, relam=%u, relfilenode=%u, reltablespace=%u, " \
			  "relpages=%d, reltuples=%f, reltoastrelid=%u, reltoastidxid=%u, " \
			  "relhasindex=%c, relisshared=%c, relkind=%c, relnatts=%d, " \
			  "relchecks=%d, reltriggers=%d, relukeys=%d, relfkeys=%d, " \
			  "relrefs=%d, relhasoids=%c, relhaspkey=%c, relhasrules=%c, " \
			  "relhassubclass=%c, ...}",								\
			  (rel), NameStr((rel)->relname), (rel)->relnamespace, \
			  (rel)->reltype, (rel)->relowner, (rel)->relam, (rel)->relfilenode, \
			  (rel)->reltablespace, (rel)->relpages, (rel)->reltuples, \
			  (rel)->reltoastrelid, (rel)->reltoastidxid, (rel)->relhasindex ? 'y' : 'n', \
			  (rel)->relisshared ? 'y' : 'n', (rel)->relkind, (rel)->relnatts, \
			  (rel)->relchecks,	(rel)->reltriggers, (rel)->relukeys, (rel)->relfkeys, \
			  (rel)->relrefs, (rel)->relhasoids ? 'y' : 'n', (rel)->relhaspkey ? 'y' : 'n', \
			  (rel)->relhasrules ? 'y' : 'n', (rel)->relhassubclass ? 'y' : 'n')
#define seldump_pg_attribute(att)										\
	selnotice("pg_attribute (%p) { attrelid=%u, attname='%s', atttypid=%u, " \
			  "attstattarget=%d, attlen=%d, attnum=%d, attndims=%d, attcacheoff=%d, " \
			  "atttypmod=%d, attbyval=%c, attstorage=%c, attalign=%d, attnotnull=%c, " \
			  "atthasdef=%c, attisdropped=%c, attislocal=%c, attinhcount=%d }", \
			  (att), (att)->attrelid, NameStr((att)->attname), (att)->atttypid, \
			  (att)->attstattarget, (att)->attlen, (att)->attnum, (att)->attndims, \
			  (att)->attcacheoff, (att)->atttypmod,	(att)->attbyval, (att)->attstorage, \
			  (att)->attalign, (att)->attnotnull ? 'y' : 'n', (att)->atthasdef ? 'y' : 'n', \
			  (att)->attisdropped ? 'y' : 'n', (att)->attislocal ? 'y' : 'n', (att)->attinhcount)

/* The definition of object classes/access vectors are defined at libselinux-devel */
#ifndef SECCLASS_DB_DATABASE		/* for legacy selinux/flask.h */
#define SECCLASS_DB_DATABASE			(62)		/* next to SECCLASS_MEMPROTECT */
#define SECCLASS_DB_TABLE			(SECCLASS_DB_DATABASE + 1)
#define SECCLASS_DB_PROCEDURE			(SECCLASS_DB_DATABASE + 2)
#define SECCLASS_DB_COLUMN			(SECCLASS_DB_DATABASE + 3)
#define SECCLASS_DB_TUPLE			(SECCLASS_DB_DATABASE + 4)
#define SECCLASS_DB_BLOB			(SECCLASS_DB_DATABASE + 5)
#endif

#ifndef COMMON_DATABASE__CREATE		/* for legacy selinux/av_permission.h */
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
#endif

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
extern char *sepgsqlGetTupleName(Oid relid, HeapTuple tuple);
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
extern void  sepgsqlVerifyQuery(Query *query);
extern Oid   sepgsqlPreparePlanCheck(Relation rel);
extern void  sepgsqlRestorePlanCheck(Relation rel, Oid pgace_saved);

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
extern bool sepgsqlCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata);
extern void sepgsqlAlterProcedureContext(Relation rel, HeapTuple tuple, char *context);

/* COPY */
extern void sepgsqlCopyTable(Relation rel, List *attnumlist, bool is_from);
extern bool sepgsqlCopyToTuple(Relation rel, HeapTuple tuple);
extern bool sepgsqlCopyFromTuple(Relation rel, HeapTuple tuple);

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
extern char *sepgsqlSecurityLabelNotFound(Oid sid);

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
extern bool sepgsqlNodeIsSecurityLabel(DefElem *defel);
extern Oid sepgsqlParseSecurityLabel(DefElem *defel);

#endif /* SEPGSQL_INTERNAL_H */
