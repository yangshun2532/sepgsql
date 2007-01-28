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

/* security enhanced selinux core implementation */
extern Size  sepgsql_shmem_size(void);
extern int   sepgsql_avc_permission(psid ssid, psid tsid, uint16 tclass,
									uint32 perms, char **audit);
extern psid  sepgsql_avc_createcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_avc_relabelcon(psid ssid, psid tsid, uint16 tclass);
extern psid  sepgsql_context_to_psid(char *context);
extern char *sepgsql_psid_to_context(psid sid);
extern bool  sepgsql_check_context(char *context);
extern void  sepgsqlInitialize(void);
extern int   sepgsqlInitializePostmaster(void);
extern void  sepgsqlFinalizePostmaster(void);

/* utility functions */
extern psid sepgsqlGetServerPsid(void);
extern psid sepgsqlGetClientPsid(void);
extern void sepgsqlSetClientPsid(psid new_ctx);
extern psid sepgsqlGetDatabasePsid(void);
extern bool sepgsqlAttributeIsPsid(Form_pg_attribute attr);
extern bool sepgsqlIsEnabled(void);

/* SE-PostgreSQL core Security Functions */
extern List *sepgsqlWalkExpr(List *selist, Query *query, Node *);
extern List *sepgsqlRewriteQuery(Query *query);
extern List *sepgsqlRewriteQueryList(List *queryList);
extern void sepgsqlVerifyQuery(Query *query);
extern void sepgsqlVerifyQueryList(List *queryList);

/* SE-PostgreSQL hard-coded trigger functions */
extern HeapTuple sepgsqlExecInsert(HeapTuple newtup, Relation rel, MemoryContext mcontext);
extern HeapTuple sepgsqlExecUpdate(HeapTuple newtup, HeapTuple oldtup, Relation rel);

/* CREATE/ALTER/DROP DATABASE statement related */
extern void sepgsqlCreateDatabase(Datum *values, char *nulls);
extern void sepgsqlDropDatabase(Form_pg_database pgdat);
extern void sepgsqlAlterDatabase(Form_pg_database pgdat);
extern psid sepgsqlAlterDatabaseContext(Form_pg_database pgdat, char *newcon);

/* CREATE/ALTER/DROP TABLE statement related */
extern Query *sepgsqlProxyCreateTable(Query *query);
extern TupleDesc sepgsqlCreateRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc);
extern TupleDesc sepgsqlCloneRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc);
extern void sepgsqlPutRelationContext(Form_pg_class pg_class);
extern void sepgsqlPutSysAttributeContext(Form_pg_attribute pg_attr, AttrNumber attnum);

extern void sepgsqlAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd);
extern void sepgsqlAlterTableAddColumn(Relation rel, Form_pg_attribute pg_attr);
extern void sepgsqlAlterTableSetTableContext(Relation rel, Value *newcon);
extern void sepgsqlAlterTableSetColumnContext(Relation rel, char *name, Value *newcon);

/* CREATE/ALTER/DROP FUNCTION statement related */
extern Query *sepgsqlProxyCreateProcedure(Query *query);
extern void sepgsqlCreateProcedure(Datum *values, char *nulls);
extern void sepgsqlAlterProcedure(Form_pg_proc pg_proc, AlterFunctionStmt *stmt);
extern void sepgsqlExecInitExpr(ExprState *state, PlanState *parent);

/* COPY FROM/COPY TO statement */
extern void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from);
extern bool sepgsqlCopyTo(Relation rel, HeapTuple tuple);

/* bootstrap hooks */
extern int sepgsqlBootstrapInsertOneValue(int index);
extern void sepgsqlBootstrapFormrdesc(Relation rel);
extern void sepgsqlBootstrapPostCreateRelation(Oid relid);
extern bool sepgsqlBootstrapPgSelinuxAvailable(void);
extern psid sepgsqlBootstrapContextToPsid(char *context);
extern char *sepgsqlBootstrapPsidToContext(psid psid);

/* SQL functions */
extern Datum psid_in(PG_FUNCTION_ARGS);
extern Datum psid_out(PG_FUNCTION_ARGS);
extern Datum text_to_psid(PG_FUNCTION_ARGS);
extern Datum psid_to_text(PG_FUNCTION_ARGS);
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_tuple_perm(PG_FUNCTION_ARGS);

#else
/* dummy enhanced selinux core implementation */
static inline void sepgsqlInitialize(void) {}
static inline int  sepgsqlInitializePostmaster(void) { return 0; }
static inline void sepgsqlFinalizePostmaster(void) {}
static inline Query *sepgsqlProxy(Query *query) { return query; }

/* dummy CREATE DATABASE statement */
static inline void selinuxHookCreateDatabase(Datum *values, char *nulls) {}

/* dummy CREATE/ALTER/DROP TABLE statement related */
static inline void selinuxHookAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd) {}
static inline void selinuxHookAlterTableAddColumn(Relation rel, Form_pg_attribute pg_attr) {}

/* dummy CREATE PROCEDURE statement */
static inline void selinuxHookCreateProcedure(Datum *values, char *nulls) {}
static inline void selinuxHookAlterProcedure(Form_pg_proc *pg_proc, AlterFunctionStmt *stmt) {}

#define selinuxPrepareExecProcedure(func)
#define selinuxRestoreExecProcedure

/* dummy COPY FROM/COPY TO statement */
static inline void selinuxHookDoCopy(Relation rel, List *attnumlist, bool is_from) {}
static inline void selinuxHookCopyFrom(Relation rel, Datum *values, char *nulls) {}
static inline Node *selinuxHookCopyFromNewContext(Relation rel) { return NULL; }
static inline bool selinuxHookCopyTo(Relation rel, HeapTuple tuple) { return true; }

/* dummy libselinux wrapper functions */
static inline Size sepgsql_shmem_size(void) { return 0; }

/* dummy utility functions */
static inline psid sepgsqlComputeImplicitContext(Oid relid, psid relselcon, uint16 *tclass) { return InvalidOid; }
static inline bool sepgsqlAttributeIsPsid(Form_pg_attribute attr) { return false; }

#endif /* HAVE_SELINUX */
#endif /* SEPGSQL_H */
