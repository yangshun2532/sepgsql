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
#include "nodes/parsenodes.h"
#include "utils/rel.h"

#define selerror(fmt, ...)		\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))
#define seldenied(fmt, ...)		\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_DENIED), errmsg(fmt, ##__VA_ARGS__)))
#define selnotice(fmt, ...)		\
	ereport(NOTICE, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))

static inline void selinux_audit(int result, char *message) {
	if (message != NULL) {
		if (result != 0) {
			ereport(ERROR, (errcode(ERRCODE_SELINUX_DENIED),
							errmsg("SELinux: %s", message)));
		} else {
			ereport(NOTICE, (errcode(ERRCODE_SELINUX_INTERNAL),
							 errmsg("SELinux: %s", message)));
		}
	} else if (result != 0) {
		ereport(ERROR, (errcode(ERRCODE_SELINUX_DENIED),
						"SELinux access denied without any audit messages."));
	}
}

#ifdef HAVE_SELINUX
/* security enhanced selinux core implementation */
extern psid selinuxGetServerPsid(void);
extern psid selinuxGetClientPsid(void);
extern psid selinuxGetDatabasePsid(void);
extern void selinuxInitialize(void);

/* CREATE DATABASE statement related */
extern void selinuxHookCreateDatabase(Datum *values, char *nulls);

/* CREATE TABLE statement related */
extern Query *selinuxProxyCreateTable(Query *query);		
extern void selinuxHookCreateRelation(TupleDesc tupDesc, char relkind, List *schema);
extern void selinuxHookCloneRelation(TupleDesc tupDesc, Relation rel);
extern void selinuxHookPutRelselcon(Form_pg_class pg_class);
extern void selinuxHookPutSysAttselcon(Form_pg_attribute pg_attr, int attnum);

/* COPY FROM/COPY TO statement */
extern void selinuxHookDoCopy(Relation rel, List *attnumlist, bool is_from);
extern void selinuxHookCopyFrom(Relation rel, Datum *values, char *nulls);
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

#else

/* dummy CREATE DATABASE statement */
static inline void selinuxHookCreateDatabase(Datum *values, char *nulls)
{}

#endif /* HAVE_SELINUX */
#endif /* SEPGSQL_H */
