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

/*
 * SE-PostgreSQL core functions
 *   src/backend/security/sepgsqlCore.c
 */
#ifdef HAVE_SELINUX
extern Size  sepgsql_shmem_size(void);
extern void  sepgsqlInitialize(void);
extern int   sepgsqlInitializePostmaster(void);
extern void  sepgsqlFinalizePostmaster(void);
extern bool  sepgsqlIsEnabled(void);
#else
#define sepgsql_shmem_size()				(0)
#define sepgsqlInitialize()
#define sepgsqlInitializePostmaster()		(0)
#define sepgsqlFinalizePostmaster()
#define sepgsqlIsEnabled()					(false)
#endif

/*
 * SE-PostgreSQL proxy functions
 *   src/backend/security/sepgsqlProxy.c
 */
#ifdef HAVE_SELINUX
extern List *sepgsqlProxyQueryList(List *queryList);
extern void *sepgsqlForeignKeyPrepare(const char *querystr, int nargs, Oid *argtypes);
#else
#define sepgsqlProxyQueryList(a)			(a)
#endif

/*
 * SE-PostgreSQL checking function
 *   src/backend/security/sepgsqlVerify.c
 */
#ifdef HAVE_SELINUX
extern void sepgsqlVerifyQueryList(List *queryList);
#else
#define sepgsqlVerifyQueryList(a)
#endif

/*
 * SE-PostgreSQL hooks
 *   src/backend/security/sepgsqlHooks.c
 */
#ifdef HAVE_SELINUX
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
extern void sepgsqlGetParamDatabase(void);
extern void sepgsqlSetParamDatabase(void);

/* RELATION/ATTRIBUTE */
extern void sepgsqlAlterTableSetTableContext(Relation rel, Value *context);
extern void sepgsqlAlterTableSetColumnContext(Relation rel, char *colname, Value *context);
extern void sepgsqlLockTable(Oid relid);

/* PROCEDURE */
extern void sepgsqlExecInitExpr(ExprState *state, PlanState *parent);
extern void sepgsqlAlterProcedureContext(Relation rel, HeapTuple tuple, char *context);

/* COPY */
extern void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from);
extern bool sepgsqlCopyTo(Relation rel, HeapTuple tuple);
#else
/* simple_heap_xxxx hooks */
#define sepgsqlSimpleHeapInsert(a,b)
#define sepgsqlSimpleHeapUpdate(a,b,c)
#define sepgsqlSimpleHeapDelete(a,b)
/* heap_xxxx hooks for implicit labeling */
#define sepgsqlHeapInsert(a,b)
#define sepgsqlHeapUpdate(a,b,c)
/* INSERT/UPDATE/DELETE statement hooks */
#define sepgsqlExecInsert(a,b,c)					(true)
#define sepgsqlExecUpdate(a,b,c,d)					(true)
#define sepgsqlExecDelete(a,b,c)					(true)
/* DATABASE */
#define sepgsqlAlterDatabaseContext(a,b,c)
#define sepgsqlGetParamDatabase()
#define sepgsqlSetParamDatabase()
/* TABLE/COLUMN */
#define sepgsqlAlterTableSetTableContext(a,b)
#define sepgsqlAlterTableSetColumnContext(a,b,c)
#define sepgsqlLockTable(a)
/* PROCEDURE */
#define sepgsqlExecInitExpr(a,b)
#define sepgsqlAlterProcedureContext(a,b,c)
/* COPY TO/COPY FROM */
#define sepgsqlDoCopy(a,b,c)
#define sepgsqlCopyTo(a,b)								(true)
#endif

/*
 * SE-PostgreSQL Binary Large Object (BLOB) functions
 *   src/backend/security/sepgsqlLargeObject.c
 */
#ifdef HAVE_SELINUX
extern psid sepgsqlLargeObjectGetattr(Oid loid);
extern void sepgsqlLargeObjectSetattr(Oid loid, psid lo_security);
extern void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectWrite(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectImport(void);
extern void sepgsqlLargeObjectExport(void);
#else
#define sepgsqlLargeObjectGetattr(a)
#define sepgsqlLargeObjectSetattr(a,b)
#define sepgsqlLargeObjectRead(a,b)
#define sepgsqlLargeObjectWrite(a,b)
#define sepgsqlLargeObjectImport()
#define sepgsqlLargeObjectExport()
#endif

/*
 * SE-PostgreSQL SQL functions
 */
extern Datum psid_in(PG_FUNCTION_ARGS);
extern Datum psid_out(PG_FUNCTION_ARGS);
extern Datum text_to_psid(PG_FUNCTION_ARGS);
extern Datum psid_to_text(PG_FUNCTION_ARGS);
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

#endif /* SEPGSQL_H */
