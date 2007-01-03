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
#include "catalog/pg_proc.h"
#include "nodes/parsenodes.h"
#include "utils/rel.h"

#define selerror(fmt, ...)											\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))
#define seldenied(fmt, ...)		\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_DENIED), errmsg(fmt, ##__VA_ARGS__)))
#define selnotice(fmt, ...)		\
	ereport(NOTICE, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))
#define seldebug(fmt, ...)		\
	ereport(DEBUG1, (errcode(ERRCODE_SELINUX_INTERNAL),		\
					 errmsg("%s(%d): " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)))

static inline void selinux_audit(int result, char *message, char *objname) {
	int errlv = (result ? ERROR : NOTICE);

	if (message) {
		if (objname) {
			ereport(errlv, (errcode(ERRCODE_SELINUX_DENIED),
							errmsg("SELinux: %s name=%s", message, objname)));
		} else {
			ereport(errlv, (errcode(ERRCODE_SELINUX_DENIED),
							errmsg("SELinux: %s", message)));
		}
	} else if (result != 0)
		ereport(ERROR, (errcode(ERRCODE_SELINUX_DENIED),
						"SELinux access denied without any audit messages."));
}

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
extern psid sepgsqlGetServerPsid(void);
extern psid sepgsqlGetClientPsid(void);
extern void sepgsqlSetClientPsid(psid new_ctx);
extern psid sepgsqlGetDatabasePsid(void);
extern void sepgsqlInitialize(void);
extern int sepgsqlInitializePostmaster(void);
extern void sepgsqlFinalizePostmaster(void);
extern Query *sepgsqlProxy(Query *query);

/* SELECT statement related */
extern Query *selinuxProxySelect(Query *query);
extern void selinuxCheckRteRelation(Query *query, RangeTblEntry *rte, int index);
extern void selinuxCheckTargetList(Query *query, List *targetList);
extern void selinuxCheckExpr(Query *query, Expr *expr);
/* UPDATE statement related */
extern Query *selinuxProxyUpdate(Query *query);

/* INSERT statement related */
extern Query *selinuxProxyInsert(Query *query);

/* DELETE statement related */
extern Query *selinuxProxyDelete(Query *query);

/* CREATE DATABASE statement related */
extern void selinuxHookCreateDatabase(Datum *values, char *nulls);

/* CREATE/ALTER/DROP TABLE statement related */
extern Query *selinuxProxyCreateTable(Query *query);
extern TupleDesc selinuxHookCreateRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc);
extern TupleDesc selinuxHookCloneRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc);
extern void selinuxHookPutRelationContext(Form_pg_class pg_class);
extern void selinuxHookPutSysAttributeContext(Form_pg_attribute pg_attr, AttrNumber attnum);

extern void selinuxHookAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd);
extern void selinuxHookAlterTableAddColumn(Relation rel, Form_pg_attribute pg_attr);
extern void selinuxHookAlterTableSetTableContext(Relation rel, Value *newcon);
extern void selinuxHookAlterTableSetColumnContext(Relation rel, char *name, Value *newcon);

/* CREATE/ALTER/DROP FUNCTION statement related */
extern Query *selinuxProxyCreateProcedure(Query *query);
extern void selinuxHookCreateProcedure(Datum *values, char *nulls);
extern void selinuxHookAlterProcedure(Form_pg_proc pg_proc, AlterFunctionStmt *stmt);
extern psid selinuxHookPrepareProcedure(Oid funcid);
extern void selinuxHookRestoreProcedure(psid orig_psid);
#define selinuxPrepareExecProcedure(funcid)					   \
	do {													   \
		psid __selinux_ctx_backup =							   \
			selinuxHookPrepareProcedure(funcid);			   \
		PG_TRY()

#define selinuxRestoreExecProcedure()						   \
		PG_CATCH();											   \
		{													   \
			selinuxHookRestoreProcedure(__selinux_ctx_backup); \
			PG_RE_THROW();									   \
		}													   \
		PG_END_TRY();										   \
		selinuxHookRestoreProcedure(__selinux_ctx_backup);	   \
	} while(0)

/* COPY FROM/COPY TO statement */
extern void selinuxHookDoCopy(Relation rel, List *attnumlist, bool is_from);
extern void selinuxHookCopyFrom(Relation rel, Datum *values, char *nulls);
extern Node *selinuxHookCopyFromNewContext(Relation rel);
extern bool selinuxHookCopyTo(Relation rel, HeapTuple tuple);

/* bootstrap hooks */
extern int selinuxBootstrapInsertOneValue(int index);
extern void selinuxBootstrapFormrdesc(Relation rel);
extern void selinuxBootstrapPostCreateRelation(Oid relid);

/* SQL functions */
extern Datum psid_in(PG_FUNCTION_ARGS);
extern Datum psid_out(PG_FUNCTION_ARGS);
extern Datum psid_recv(PG_FUNCTION_ARGS);
extern Datum psid_send(PG_FUNCTION_ARGS);
extern Datum text_to_psid(PG_FUNCTION_ARGS);
extern Datum psid_to_text(PG_FUNCTION_ARGS);
extern Datum psid_to_bpchar(PG_FUNCTION_ARGS);
extern Datum bpchar_to_psid(PG_FUNCTION_ARGS);

extern Datum selinux_getcon(PG_FUNCTION_ARGS);
extern Datum selinux_permission(PG_FUNCTION_ARGS);
extern Datum selinux_permission_noaudit(PG_FUNCTION_ARGS);
extern Datum selinux_check_context_insert(PG_FUNCTION_ARGS);
extern Datum selinux_check_context_update(PG_FUNCTION_ARGS);

/* libselinux wrapper functions */
extern Size sepgsql_shmem_size(void);
extern void sepgsql_init_libselinux(void);
extern void sepgsql_avc_reset(void);
extern int sepgsql_avc_permission(psid ssid, psid tsid, uint16 tclass, uint32 perms, char **audit);
extern psid sepgsql_avc_createcon(psid ssid, psid tsid, uint16 tclass);
extern psid sepgsql_avc_relabelcon(psid ssid, psid tsid, uint16 tclass);
extern psid sepgsql_context_to_psid(char *context);
extern char *sepgsql_psid_to_context(psid sid);
extern bool sepgsql_check_context(char *context);
extern psid sepgsql_getcon(void);
extern psid sepgsql_getpeercon(int sockfd);

/* utility functions */
extern psid sepgsqlComputeImplicitContext(Oid relid, psid relselcon, uint16 *tclass);
extern bool sepgsqlAttributeIsPsid(Form_pg_attribute attr);

#else
/* dummy enhanced selinux core implementation */
static inline void selinuxInitialize(void) {}
static inline int selinuxInitializePostmaster(void) { return 0; }
static inline void selinuxFinalizePostmaster(void) {}
static inline void selinuxHookPolicyStateChanged(void) {}
static inline Query *selinuxProxy(Query *query) { return query; }

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
static inline bool selinuxAttributeIsPsid(Form_pg_attribute attr) { return false; }
static inline void selinuxSetColumnDefIsPsid(ColumnDef *column) {}

#endif /* HAVE_SELINUX */
#endif /* SEPGSQL_H */
