/*
 * src/include/sepgsql.h
 *    The header file of Security Enhanced PostgreSQL
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

#define selerror(fmt, ...)		\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))
#define seldenied(fmt, ...)		\
	ereport(ERROR, (errcode(ERRCODE_SELINUX_DENIED), errmsg(fmt, ##__VA_ARGS__)))
#define selnotice(fmt, ...)		\
	ereport(NOTICE, (errcode(ERRCODE_SELINUX_INTERNAL), errmsg(fmt, ##__VA_ARGS__)))

#ifdef HAVE_SELINUX


/* libselinux wrapper functions */
extern void libselinux_avc_reset(void);
extern int libselinux_avc_permission(Psid ssid, Psid tsid, uint16 tclass, uint32 perms, char **audit);
extern Psid libselinux_avc_createcon(Psid ssid, Psid tsid, uint16 tclass);
extern Psid libselinux_avc_relabelcon(Psid ssid, Psid tsid, uint16 tclass);
extern Psid libselinux_context_to_psid(char *context);
extern char *libselinux_psid_to_context(Psid psid);
extern bool libselinux_check_context(char *context);
extern Psid libselinux_getcon(void);
extern Psid libselinux_getpeercon(int sockfd);

#else

#endif /* HAVE_SELINUX */
#endif /* SEPGSQL_H */
