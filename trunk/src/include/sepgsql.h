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

static inline void sepgsql_audit(int result, char *message, char *objname) {
	int errlv = (result ? ERROR : NOTICE);

	if (message) {
		if (objname) {
			ereport(errlv, (errcode(ERRCODE_INTERNAL_ERROR),
							errmsg("SELinux: %s name=%s", message, objname)));
		} else {
			ereport(errlv, (errcode(ERRCODE_INTERNAL_ERROR),
							errmsg("SELinux: %s", message)));
		}
	} else if (result != 0)
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR),
						"SELinux access denied without any audit messages."));
}

#define TUPLE_SELCON	"security_context"

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
#define DATABASE__CREATE_OBJ                      0x00000080UL
#define DATABASE__DROP_OBJ                        0x00000100UL
#define DATABASE__LOAD_MODULE                     0x00000200UL
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

/*
 * SE-PostgreSQL core implementation
 *   src/backend/selinux/sepgsql.c
 */
extern Size  sepgsql_shmem_size(void);
extern int   sepgsql_avc_permission(psid ssid, psid tsid, uint16 tclass,
									uint32 perms, char **audit);
extern psid  sepgsql_avc_createcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_avc_relabelcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_context_to_psid(char *context);
extern char *sepgsql_psid_to_context(psid sid);
extern bool  sepgsql_check_context(char *context);

extern Datum psid_in(PG_FUNCTION_ARGS);
extern Datum psid_out(PG_FUNCTION_ARGS);
extern Datum text_to_psid(PG_FUNCTION_ARGS);
extern Datum psid_to_text(PG_FUNCTION_ARGS);
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);

extern void  sepgsqlInitialize(void);
extern int   sepgsqlInitializePostmaster(void);
extern void  sepgsqlFinalizePostmaster(void);

extern psid  sepgsqlGetServerPsid(void);
extern psid  sepgsqlGetClientPsid(void);
extern void  sepgsqlSetClientPsid(psid new_ctx);
extern psid  sepgsqlGetDatabasePsid(void);
extern bool  sepgsqlAttributeIsPsid(Form_pg_attribute attr);
extern bool  sepgsqlIsEnabled(void);

/*
 * SE-PostgreSQL Bootstraping Hooks
 *   src/backend/selinux/bootstrap.c
 */
extern bool  sepgsqlBootstrapPgSelinuxAvailable(void);
extern psid  sepgsqlBootstrapContextToPsid(char *context);
extern char *sepgsqlBootstrapPsidToContext(psid psid);
extern HeapTuple sepgsqlInsertOneTuple(HeapTuple tuple, Relation rel);

/*
 * Query rewriting proxy functions
 *   src/backend/selinux/rewrite.c
 */
extern List *sepgsqlWalkExpr(List *selist, Query *query, Node *);
extern List *sepgsqlRewriteQuery(Query *query);
extern List *sepgsqlRewriteQueryList(List *queryList);
extern void *sepgsqlForeignKeyPrepare(const char *querystr, int nargs, Oid *argtypes);

/*
 * Query checking functions
 *   src/backend/selinux/check_perms.c
 */
extern void  sepgsqlVerifyQuery(Query *query);
extern void  sepgsqlVerifyQueryList(List *queryList);
extern Datum sepgsql_tuple_perm(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perm_abort(PG_FUNCTION_ARGS);
extern bool  sepgsql_tuple_perm_copyto(Relation rel,
									   HeapTuple tuple,
									   uint32 perms);
extern HeapTuple sepgsqlExecInsert(HeapTuple newtup,
								   MemoryContext mcontext,
								   Relation rel,
								   ProjectionInfo *retProj);
extern void sepgsqlExecUpdate(HeapTuple newtup,
							  HeapTuple oldtup,
							  Relation rel,
							  ProjectionInfo *retProj);
extern void  sepgsqlExecDelete(HeapTuple newtup,
							   Relation rel,
							   ProjectionInfo *retProj);

/*
 * COPY TO/COPY FROM statement related hooks
 *   src/backend/selinux/copy.c
 */
extern void  sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from);
extern bool  sepgsqlCopyTo(Relation rel, HeapTuple tuple);

/*
 * DATABASE statement related hooks
 *   src/backend/selinux/database.c
 */
extern void  sepgsqlCreateDatabase(Datum *values, char *nulls);
extern void  sepgsqlDropDatabase(Form_pg_database pgdat);
extern void  sepgsqlAlterDatabase(Form_pg_database pgdat);
extern psid  sepgsqlAlterDatabaseContext(Form_pg_database pgdat, char *newcon);

/*
 * PROCEDURE statement related hooks
 *   src/backend/selinux/procedure.c
 */
extern void  sepgsqlCreateProcedure(Datum *values, char *nulls);
extern void  sepgsqlAlterProcedure(Form_pg_proc pg_proc, AlterFunctionStmt *stmt);
extern void  sepgsqlExecInitExpr(ExprState *state, PlanState *parent);

/*
 * TABLE statement related hooks
 *   src/backend/selinux/relation.c
 */
extern TupleDesc sepgsqlCreateRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc);
extern TupleDesc sepgsqlCloneRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc);
extern void sepgsqlPutRelationContext(Form_pg_class pg_class);
extern void sepgsqlPutSysAttributeContext(Form_pg_attribute pg_attr, AttrNumber attnum);

extern void sepgsqlAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd);
extern void sepgsqlAlterTableAddColumn(Relation rel, Form_pg_attribute pg_attr);
extern void sepgsqlAlterTableSetTableContext(Relation rel, Value *newcon);
extern void sepgsqlAlterTableSetColumnContext(Relation rel, char *name, Value *newcon);

#else  /* HAVE_SELINUX */

/*
 * SE-PostgreSQL core implementation
 *   src/backend/selinux/sepgsql.c
 */
#define sepgsql_shmem_size()					0
#define sepgsqlInitialize()
#define sepgsqlInitializePostmaster()			0
#define sepgsqlFinalizePostmaster()
#define sepgsqlAttributeIsPsid(x)				(false)
#define sepgsqlIsEnabled()						(false)

/*
 * SE-PostgreSQL Bootstraping Hooks
 *   src/backend/selinux/bootstrap.c
 */
#define sepgsqlInsertOneTuple(a, b)				(a)

/*
 * Query rewriting proxy functions
 *   src/backend/selinux/rewrite.c
 */
#define sepgsqlRewriteQueryList(a)				(a)
#define sepgsqlForeignKeyPrepare(a,b,c)			(SPI_prepare((a),(b),(c)))

/*
 * Query checking functions
 *   src/backend/selinux/check_perms.c
 */
#define sepgsqlVerifyQueryList(a)
#define sepgsql_tuple_perm_copyto(a,b,c)		(true)
#define sepgsqlExecInsert(a,b,c,d)				(a)
#define sepgsqlExecUpdate(a,b,c,d)
#define sepgsqlExecDelete(a,b,c)

/*
 * COPY TO/COPY FROM statement related hooks
 *   src/backend/selinux/copy.c
 */
#define sepgsqlDoCopy(a,b,c)
#define sepgsqlCopyTo(a,b)						(true)

/*
 * DATABASE statement related hooks
 *   src/backend/selinux/database.c
 */
static inline void sepgsqlCreateDatabase(Datum *values, char *nulls) {
	values[Anum_pg_database_datselcon - 1] = InvalidOid;
	nulls[Anum_pg_database_datselcon - 1] = 'n';
}
#define sepgsqlDropDatabase(a)
#define sepgsqlAlterDatabase(a)

/*
 * PROCEDURE statement related hooks
 *   src/backend/selinux/procedure.c
 */
static inline void sepgsqlCreateProcedure(Datum *values, char *nulls) {
	values[Anum_pg_proc_proselcon - 1] = InvalidOid;
	nulls[Anum_pg_proc_proselcon - 1] = 'n';
}
#define sepgsqlAlterProcedure(a,b)
#define sepgsqlExecInitExpr(a,b)

/*
 * TABLE statement related hooks
 *   src/backend/selinux/relation.c
 */
#define sepgsqlCreateRelation(a,b,c,d)			(d)
#define sepgsqlCloneRelation(a,b,c,d)			(d)
static inline void sepgsqlPutRelationContext(Form_pg_class pgclass) {
	pgclass->relselcon = InvalidOid;
}
static inline void sepgsqlPutSysAttributeContext(Form_pg_attribute attr,
												 AttrNumber attnum) {
	attr->attselcon = InvalidOid;
}
#define sepgsqlAlterTable(a,b,c,d)
#define sepgsqlAlterTableAddColumn(a,b)

#endif /* HAVE_SELINUX */
#endif /* SEPGSQL_H */
