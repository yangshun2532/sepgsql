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
#include "nodes/parsenodes.h"
#include "utils/rel.h"

#define selerror(fmt, ...)		\
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
/* security enhanced selinux core implementation */
extern psid selinuxGetServerPsid(void);
extern psid selinuxGetClientPsid(void);
extern void selinuxSetClientPsid(psid new_ctx);
extern psid selinuxGetDatabasePsid(void);
extern void selinuxInitialize(void);
extern int selinuxInitializePostmaster(void);
extern void selinuxFinalizePostmaster(void);
extern void selinuxHookPolicyStateChanged(void);
extern Query *selinuxProxy(Query *query);

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

/* CREATE TABLE statement related */
extern Query *selinuxProxyCreateTable(Query *query);
extern void selinuxHookCreateRelation(TupleDesc tupDesc, char relkind, List *schema);
extern void selinuxHookCloneRelation(TupleDesc tupDesc, Relation rel);
extern void selinuxHookPutRelselcon(Form_pg_class pg_class);
extern void selinuxHookPutSysAttselcon(Form_pg_attribute pg_attr, int attnum);

/* CREATE PROCEDURE statement related */
extern Query *selinuxProxyCreateProcedure(Query *query);
extern void selinuxHookCreateProcedure(Datum *values, char *nulls);
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
extern void libselinux_avc_reset(void);
extern int libselinux_avc_permission(psid ssid, psid tsid, uint16 tclass, uint32 perms, char **audit);
extern psid libselinux_avc_createcon(psid ssid, psid tsid, uint16 tclass);
extern psid libselinux_avc_relabelcon(psid ssid, psid tsid, uint16 tclass);
extern psid libselinux_context_to_psid(char *context);
extern char *libselinux_psid_to_context(psid sid);
extern bool libselinux_check_context(char *context);
extern psid libselinux_getcon(void);
extern psid libselinux_getpeercon(int sockfd);

/* utility functions */
extern psid selinuxComputeNewTupleContext(Oid relid, psid relselcon, uint16 *tclass);
extern bool selinuxAttributeIsPsid(Form_pg_attribute attr);
extern void selinuxSetColumnDefIsPsid(ColumnDef *column);

#else
/* dummy enhanced selinux core implementation */
static inline void selinuxInitialize(void) {}
static inline int selinuxInitializePostmaster(void) { return 0; }
static inline void selinuxFinalizePostmaster(void) {}
static inline void selinuxHookPolicyStateChanged(void) {}
static inline Query *selinuxProxy(Query *query) { return query; }

/* dummy CREATE DATABASE statement */
static inline void selinuxHookCreateDatabase(Datum *values, char *nulls) {}

/* dummy CREATE PROCEDURE statement */
static inline void selinuxHookCreateProcedure(Datum *values, char *nulls) {}
#define selinuxPrepareExecProcedure(func)
#define selinuxRestoreExecProcedure

/* dummy COPY FROM/COPY TO statement */
static inline void selinuxHookDoCopy(Relation rel, List *attnumlist, bool is_from) {}
static inline void selinuxHookCopyFrom(Relation rel, Datum *values, char *nulls) {}
static inline Node *selinuxHookCopyFromNewContext(Relation rel) { return NULL; }
static inline bool selinuxHookCopyTo(Relation rel, HeapTuple tuple) { return true; }

/* dummy utility functions */
static inline bool selinuxAttributeIsPsid(Form_pg_attribute attr) { return false; }
static inline void selinuxSetColumnDefIsPsid(ColumnDef *column) {}

#endif /* HAVE_SELINUX */
#endif /* SEPGSQL_H */
