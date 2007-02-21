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
 */
extern Size  sepgsql_shmem_size(void);
extern void  sepgsqlInitialize(void);
extern int   sepgsqlInitializePostmaster(void);
extern void  sepgsqlFinalizePostmaster(void);
extern bool  sepgsqlIsEnabled(void);

/*
 * SE-PostgreSQL proxy facilities
 */
extern List *sepgsqlWalkExpr(List *selist, Query *query, Node *);
extern List *sepgsqlProxyQuery(Query *query);
extern List *sepgsqlProxyQueryList(List *queryList);
extern void *sepgsqlForeignKeyPrepare(const char *querystr, int nargs, Oid *argtypes);
extern void sepgsqlVerifyQuery(Query *query);
extern void sepgsqlVerifyQueryList(List *queryList);

/*
 * SE-PostgreSQL heap input/output functions
 */
extern void sepgsqlSimpleHeapInsert(Relation rel, HeapTuple tuple);
extern void sepgsqlSimpleHeapUpdate(Relation rel, ItemPointer tid, HeapTuple newtup);
extern void sepgsqlSimpleHeapDelete(Relation rel, ItemPointer tid);
extern void sepgsqlExecInsert(Relation rel, HeapTuple tuple, bool has_returing);
extern void sepgsqlExecUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup, bool has_returning);
extern void sepgsqlExecDelete(Relation rel, HeapTuple tuple);
extern void sepgsqlHeapInsert(Relation rel, HeapTuple tuple);
extern void sepgsqlHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup);

/*
 * SE-PostgreSQL hooks
 */
/* DATABASE */
extern void sepgsqlAlterDatabaseContext(Relation rel, HeapTuple tuple, char *new_context);

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

/* SE-PostgreSQL SQL function */
extern Datum psid_in(PG_FUNCTION_ARGS);
extern Datum psid_out(PG_FUNCTION_ARGS);
extern Datum text_to_psid(PG_FUNCTION_ARGS);
extern Datum psid_to_text(PG_FUNCTION_ARGS);
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

/* Binary Large Object (BLOB) related hooks */
extern void sepgsqlLargeObjectCreate(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectDrop(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectGetattr(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectSetattr(Relation rel, HeapTuple oldtup, HeapTuple newtup);
extern void sepgsqlLargeObjectRead(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectWrite(Relation rel, HeapTuple tuple);
extern void sepgsqlLargeObjectImport(void);
extern void sepgsqlLargeObjectExport(void);

#endif /* SEPGSQL_H */
