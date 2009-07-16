/*
 * src/include/security/sepgsql.h
 *    Headers of SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

#include "access/htup.h"
#include "fmgr.h"
#include "nodes/parsenodes.h"
#include "utils/relcache.h"
#include <selinux/selinux.h>

#ifdef HAVE_SELINUX
/* GUC parameter to turn on/off SE-PostgreSQL */
extern bool sepostgresql_enabled;

/* GUC parameter to turn on/off mcstrans */
extern bool sepostgresql_mcstrans;

/* Objject classes and permissions internally used */
enum SepgsqlClasses
{
	SEPG_CLASS_DB_DATABASE = 0,
	SEPG_CLASS_DB_SCHEMA,
	SEPG_CLASS_DB_SCHEMA_TEMP,
	SEPG_CLASS_DB_PROCEDURE,
	SEPG_CLASS_MAX,
};

/* Permission bits internally used */
#define SEPG_DB_DATABASE__CONNECT			(1<<6)
#define SEPG_DB_DATABASE__SUPERUSER			(1<<9)

#define SEPG_DB_SCHEMA__USAGE				(1<<6)

#define SEPG_DB_SCHEMA_TEMP__USAGE			(SEPG_DB_SCHEMA__USAGE)

#define SEPG_DB_PROCEDURE__EXECUTE			(1<<6)

/*
 * avc.c : userspace access vector caches
 */

/* Hook to record audit logs */
typedef void (*sepgsqlAvcAuditHook_t)(bool denied,
									  const char *scontext,
									  const char *tcontext,
									  const char *tclass,
									  const char *permissions,
									  const char *audit_name);
extern PGDLLIMPORT sepgsqlAvcAuditHook_t sepgsqlAvcAuditHook;

extern void
sepgsqlAvcInitialize(void);
extern bool
sepgsqlGetEnforce(void);
extern int
sepgsqlSetEnforce(int new_mode);

extern bool
sepgsqlClientHasPermsTup(Oid relid, HeapTuple tuple,
						 uint16 tclass, uint32 required, bool abort);
extern char *
sepgsqlClientCreateLabel(char *tcontext, uint16 tclass);

extern bool
sepgsqlComputePerms(char *scontext, char *tcontext,
					uint16 tclass, uint32 required,
					const char *audit_name, bool abort);
extern char *
sepgsqlComputeCreate(char *scontext, char *tcontext, uint16 tclass);

/*
 * hooks.c : routines to check permissions
 */
extern bool
sepgsqlCheckDatabaseConnect(Oid database_oid);

extern bool
sepgsqlCheckDatabaseSuperuser(void);

extern bool
sepgsqlCheckSchemaUsage(Oid namespace_oid);

extern bool
sepgsqlCheckProcedureExecute(Oid proc_oid);

/*
 * label.c : management of security labels
 */
extern void
sepgsqlSetDefaultSecLabel(Relation rel, Datum *values, bool *nulls);
extern char *
sepgsqlGetDefaultDatabaseSecLabel(void);
extern char *
sepgsqlGetDefaultSchemaSecLabel(Oid database_oid);
extern char *
sepgsqlGetDefaultSchemaTempSecLabel(Oid database_oid);
extern char *
sepgsqlGetDefaultProcedureSecLabel(Oid namespace_oid);

extern Datum
sepgsqlGivenSecLabelIn(DefElem *new_label);
extern Datum
sepgsqlAssignDatabaseSecLabel(const char *datname, DefElem *new_label);
extern Datum
sepgsqlAssignSchemaSecLabel(const char *nspname, Oid database_oid,
							DefElem *new_label, bool is_temp);
extern Datum
sepgsqlAssignProcedureSecLabel(const char *proname, Oid namespace_oid,
							   DefElem *new_label);

extern char *
sepgsqlTransSecLabelIn(char *seclabel);
extern char *
sepgsqlTransSecLabelOut(char *seclabel);
extern char *
sepgsqlRawSecLabelIn(char *seclabel);
extern char *
sepgsqlRawSecLabelOut(char *seclabel);

/*
 * misc.c : misc functions
 */
extern char *sepgsqlGetServerLabel(void);

extern char *sepgsqlGetClientLabel(void);

extern char *sepgsqlSwitchClient(char *new_label);

extern bool sepgsqlIsEnabled(void);

/*
 * perms.c : SELinux permission related stuff
 */
extern const char *
sepgsqlAuditName(Oid relid, HeapTuple tuple);

extern security_class_t
sepgsqlTransToExternalClass(uint16 tclass_in);

extern void
sepgsqlTransToInternalPerms(security_class_t tclass_ex,
							struct av_decision *avd);
extern const char *sepgsqlGetClassString(uint16 tclass);
extern const char *sepgsqlGetPermString(uint16 tclass, uint32 permission);

#else	/* HAVE_SELINUX */
/* avc.c */
#define sepgsqlAvcInitialize()						do {} while(0)
/* hooks.c */
#define sepgsqlCheckDatabaseConnect(a)				(true)
#define sepgsqlCheckDatabaseSuperuser(a)			(true)
#define sepgsqlCheckSchemaUsage(a)					(true)
#define sepgsqlCheckProcedureExecute(a)				(true)
/* label.c */
#define sepgsqlSetDefaultSecLabel(a,b,c)			do {} while(0)
#define sepgsqlGivenSecLabelIn(a)					(PointerGetDatum(NULL))
#define sepgsqlAssignDatabaseSecLabel(a,b)			(PointerGetDatum(NULL))
#define sepgsqlAssignSchemaSecLabel(a,b,c,d)		(PointerGetDatum(NULL))
#define sepgsqlAssignProcedureSecLabel(a,b,c)		(PointerGetDatum(NULL))
/* misc.c */
#define sepgsqlIsEnabled()							(false)

#endif	/* HAVE_SELINUX */

/* SQL Functions */
extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
