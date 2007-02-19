/*
 * src/include/sepgsql.h
 *    The header file of Security Enhanced PostgreSQL
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H
#include "access/htup.h"
#include "access/tupdesc.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "nodes/execnodes.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "tcop/dest.h"
#include "utils/rel.h"

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

#define SECURITY_ATTR	"security_context"

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

#ifdef HAVE_SELINUX
/* object classes and access vectors are not included, in default */
#include <selinux/flask.h>
#define SECCLASS_DATABASE			(60)	/* next to SECCLASS_CONTEXT */
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
#define DATABASE__LOAD_MODULE                     0x00000080UL
#define DATABASE__ASSOCIATE                       0x00000100UL
#define DATABASE__CREATE_MISC                     0x00000200UL
#define DATABASE__ALTER_MISC                      0x00000400UL
#define DATABASE__DROP_MISC                       0x00000800UL
#define DATABASE__CREATE_USER                     0x00001000UL
#define DATABASE__ALTER_USER                      0x00002000UL
#define DATABASE__DROP_USER                       0x00004000UL
#define DATABASE__CREATE_VIEW                     0x00008000UL
#define DATABASE__ALTER_VIEW                      0x00010000UL
#define DATABASE__DROP_VIEW                       0x00020000UL
#define DATABASE__CREATE_TRIGGER                  0x00040000UL
#define DATABASE__ALTER_TRIGGER                   0x00080000UL
#define DATABASE__DROP_TRIGGER                    0x00100000UL
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
#endif /* HAVE_SELINUX */

/*
 * SE-PostgreSQL core functions
 */
#ifdef HAVE_SELINUX
extern Size  sepgsql_shmem_size(void);
extern int   sepgsql_avc_permission_noaudit(psid ssid,
											psid tsid,
											uint16 tclass,
											uint32 perms,
											char **audit,
											char *objname);
extern void  sepgsql_avc_permission(psid ssid,
									psid tsid,
									uint16 tclass,
									uint32 perms,
									char *objname);
extern void  sepgsql_audit(int result, char *message);
extern psid  sepgsql_avc_createcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_avc_relabelcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_context_to_psid(char *context);
extern char *sepgsql_psid_to_context(psid sid);
extern bool  sepgsql_check_context(char *context);

extern void  sepgsqlInitialize(void);
extern int   sepgsqlInitializePostmaster(void);
extern void  sepgsqlFinalizePostmaster(void);
extern bool  sepgsqlIsEnabled(void);

extern psid  sepgsqlGetServerPsid(void);
extern psid  sepgsqlGetClientPsid(void);
extern void  sepgsqlSetClientPsid(psid new_ctx);
extern psid  sepgsqlGetDatabasePsid(void);
extern char *sepgsqlGetDatabaseName(void);
#else
#define sepgsql_shmem_size()			0
#define sepgsqlInitialize()
#define sepgsqlInitializePostmaster()	0
#define sepgsqlFinalizePostmaster()
#define sepgsqlIsEnabled()				(false)
#endif

/*
 * SE-PostgreSQL proxy facilities
 */
#ifdef HAVE_SELINUX
extern List *sepgsqlWalkExpr(List *selist, Query *query, Node *);
extern List *sepgsqlProxyQuery(Query *query);
extern List *sepgsqlProxyQueryList(List *queryList);
extern void *sepgsqlForeignKeyPrepare(const char *querystr, int nargs, Oid *argtypes);
extern void sepgsqlVerifyQuery(Query *query);
extern void sepgsqlVerifyQueryList(List *queryList);
#else
#define sepgsqlProxyQueryList(x)		(x)
#define sepgsqlVerifyQueryList(x)
#endif

/*
 * SE-PostgreSQL heap input/output functions
 */
#ifdef HAVE_SELINUX
extern psid sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple);
extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, uint32 perms, bool abort);
extern void sepgsqlExecInsert(Relation rel, HeapTuple tuple, bool has_returing);
extern void sepgsqlExecUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup, bool has_returning);
extern void sepgsqlExecDelete(Relation rel, HeapTuple tuple);
extern void sepgsqlHeapInsert(Relation rel, HeapTuple tuple);
extern void sepgsqlHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup);
extern void sepgsqlSimpleHeapInsert(Relation rel, HeapTuple tuple);
extern void sepgsqlSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple tuple);
extern void sepgsqlSimpleHeapDelete(Relation rel, ItemPointer tid);
#else
#define sepgsqlCheckTuplePerms(a,b,c)
#define sepgsqlExecInsert(a,b,c)
#define sepgsqlHeapInsert(a,b)
#define sepgsqlHeapUpdate(a,b,c)
#endif

/*  DATABASE statement related hooks  */
#ifdef HAVE_SELINUX
extern void sepgsqlAlterDatabaseContext(Relation rel, HeapTuple tuple, char *new_context);
extern void sepgsqlCreateDatabase(HeapTuple tuple);
extern void sepgsqlAlterDatabase(HeapTuple tuple, char *dselcon);
extern void sepgsqlDropDatabase(HeapTuple tuple);
extern void sepgsqlCreateRole(Relation authrel, HeapTuple tuple);
extern void sepgsqlAlterRole(Relation authrel, HeapTuple newtup, HeapTuple oldtup);
extern void sepgsqlDropRole(Relation authrel, HeapTuple tuple);
#else
#define sepgsqlCreateDatabase(a)
#define sepgsqlAlterDatabase(a,b)
#define sepgsqlDropDatabase(a)
#define sepgsqlCreateRole(a,b)
#define sepgsqlAlterRole(a,b,c)
#define sepgsqlDropRole(a,b)
#endif

/*  TABLE statement related hooks  */
#ifdef HAVE_SELINUX
extern void sepgsqlCreateRelation(Relation rel, HeapTuple tuple);
extern void sepgsqlDropRelation(Relation rel, HeapTuple tuple);
extern void sepgsqlCreateAttribute(Relation rel, HeapTuple tuple);
extern void sepgsqlDropRelation(Relation rel, HeapTuple tuple);
extern void sepgsqlAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd);
extern void sepgsqlAlterTableSetTableContext(Relation rel, Value *newcon);
extern void sepgsqlAlterTableSetColumnContext(Relation rel, char *name, Value *newcon);
#else
#define sepgsqlCreateRelation(a,b)
#define sepgsqlDropRelation(a,b)
#define sepgsqlAlterTable(a,b,c,d)
#endif

/*  FUNCTION statement related hooks  */
#ifdef HAVE_SELINUX
extern void sepgsqlCreateProcedure(HeapTuple tuple);
extern void sepgsqlAlterProcedure(HeapTuple tuple, char *proselcon);
extern void sepgsqlDropProcedure(HeapTuple);
#else
#define sepgsqlCreateProcedure(a)
#define sepgsqlAlterProcedure(a,b)
#define sepgsqlDropProcedure(a)
#endif

/*  Trusted Procedure support */
#ifdef HAVE_SELINUX
extern void sepgsqlExecInitExpr(ExprState *state, PlanState *parent);
#else
#defien sepgsqlExecInitExpr(a,b)
#endif

/*  COPY TO/COPY FROM statement support */
extern void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from);
extern bool sepgsqlCopyTo(Relation rel, HeapTuple tuple);

/* Binary Large Object (BLOB) related hooks */
#ifdef HAVE_SELINUX
extern void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectGetattr(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectSetattr(Relation rel, HeapTuple oldtup, HeapTuple newtup);
extern void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectWrite(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectImport(void);
extern void sepgsqlLargeObjectExport(void);
#else
#define sepgsqlLargeObjectCreate(a,b)
#define sepgsqlLargeObjectDrop(a,b)
#define sepgsqlLargeObjectGetattr(a,b)
#define sepgsqlLargeObjectSetattr(a,b,c)
#define sepgsqlLargeObjectRead(a,b)
#define sepgsqlLargeObjectWrite(a,b)
#define sepgsqlLargeObjectImport()
#define sepgsqlLargeObjectExport()
#endif

/* SE-PostgreSQL SQL function */
extern Datum psid_in(PG_FUNCTION_ARGS);
extern Datum psid_out(PG_FUNCTION_ARGS);
extern Datum text_to_psid(PG_FUNCTION_ARGS);
extern Datum psid_to_text(PG_FUNCTION_ARGS);
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

/*
 * Internal utilities
 */
static inline char *HeapTupleGetRelationName(HeapTuple tuple) {
	Form_pg_class pgclass = (Form_pg_class) GETSTRUCT(tuple);
	return NameStr(pgclass->relname);
}

static inline char *HeapTupleGetAttributeName(HeapTuple tuple) {
	Form_pg_attribute pgattr = (Form_pg_attribute) GETSTRUCT(tuple);
	return NameStr(pgattr->attname);
}

static inline char *HeapTupleGetProcedureName(HeapTuple tuple) {
	Form_pg_proc pgproc = (Form_pg_proc) GETSTRUCT(tuple);
	return NameStr(pgproc->proname);
}

static inline char *HeapTupleGetDatabaseName(HeapTuple tuple) {
	Form_pg_database pgdat = (Form_pg_database) GETSTRUCT(tuple);
	return NameStr(pgdat->datname);
}

#endif /* SEPGSQL_H */
