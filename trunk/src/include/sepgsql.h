/*
 * src/include/sepgsql.h
 *    The header file of Security Enhanced PostgreSQL
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H
#include "utils/rel.h"

#define selerror(fmt, ...)		\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))
#define seldenied(fmt, ...)		\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_DENIED), errmsg(fmt, ##__VA_ARGS__)))
#define selnotice(fmt, ...)		\
	ereport(NOTICE, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))

#ifdef HAVE_SELINUX
/* security enhanced selinux core implementation */
extern psid selinuxGetServerPsid(void);
extern psid selinuxGetClientPsid(void);
extern psid selinuxGetDatabasePsid(void);
extern void selinuxInitialize(void);

/* bootstrap hooks */
extern int selinuxBootstrapInsertOneValue(int index);
extern void selinuxBootstrapFormrdesc(Relation rel);
extern void selinuxBootstrapPostCreateRelation(Oid relid);

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

#endif /* HAVE_SELINUX */
#endif /* SEPGSQL_H */
