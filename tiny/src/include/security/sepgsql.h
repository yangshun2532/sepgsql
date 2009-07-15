/*
 * src/include/security/sepgsql.h
 *    Headers of SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

#ifdef HAVE_SELINUX

#include "access/htup.h"
#include "fmgr.h"
#include "nodes/parsenodes.h"
#include "utils/relcache.h"
#include <selinux/selinux.h>

/* GUC parameter to turn on/off SE-PostgreSQL */
extern bool sepostgresql_enabled;

/* GUC parameter to turn on/off mcstrans */
extern bool sepostgresql_mcstrans;

/* Objject classes and permissions internally used */
enum SepgsqlClasses
{
	SEPG_CLASS_PROCESS = 0,
	SEPG_CLASS_FILE,
	SEPG_CLASS_DIR,
	SEPG_CLASS_LNK_FILE,
	SEPG_CLASS_CHR_FILE,
	SEPG_CLASS_BLK_FILE,
	SEPG_CLASS_SOCK_FILE,
	SEPG_CLASS_FIFO_FILE,
	SEPG_CLASS_DB_DATABASE,
	SEPG_CLASS_DB_SCHEMA,
	SEPG_CLASS_DB_SCHEMA_TEMP,
	SEPG_CLASS_DB_TABLE,
	SEPG_CLASS_DB_SEQUENCE,
	SEPG_CLASS_DB_PROCEDURE,
	SEPG_CLASS_DB_COLUMN,
	SEPG_CLASS_DB_TUPLE,
	SEPG_CLASS_DB_BLOB,
	SEPG_CLASS_MAX,
};

/* Permission bits internally used */
#define SEPG_PROCESS__TRANSITION			(1<<0)

#define SEPG_FILE__READ						(1<<0)
#define SEPG_FILE__WRITE					(1<<1)

#define SEPG_DIR__READ						(SEPG_FILE__READ)
#define SEPG_DIR__WRITE						(SEPG_FILE__WRITE)

#define SEPG_LNK_FILE__READ					(SEPG_FILE__READ)
#define SEPG_LNK_FILE__WRITE				(SEPG_FILE__WRITE)

#define SEPG_CHR_FILE__READ					(SEPG_FILE__READ)
#define SEPG_CHR_FILE__WRITE				(SEPG_FILE__WRITE)

#define SEPG_BLK_FILE__READ					(SEPG_FILE__READ)
#define SEPG_BLK_FILE__WRITE				(SEPG_FILE__WRITE)

#define SEPG_SOCK_FILE__READ				(SEPG_FILE__READ)
#define SEPG_SOCK_FILE__WRITE				(SEPG_FILE__WRITE)

#define SEPG_FIFO_FILE__READ				(SEPG_FILE__READ)
#define SEPG_FIFO_FILE__WRITE				(SEPG_FILE__WRITE)

#define SEPG_DB_DATABASE__CREATE			(1<<0)
#define SEPG_DB_DATABASE__DROP				(1<<1)
#define SEPG_DB_DATABASE__GETATTR			(1<<2)
#define SEPG_DB_DATABASE__SETATTR			(1<<3)
#define SEPG_DB_DATABASE__RELABELFROM		(1<<4)
#define SEPG_DB_DATABASE__RELABELTO			(1<<5)
#define SEPG_DB_DATABASE__CONNECT			(1<<6)
#define SEPG_DB_DATABASE__INSTALL_MODULE	(1<<7)
#define SEPG_DB_DATABASE__LOAD_MODULE		(1<<8)
#define SEPG_DB_DATABASE__SUPERUSER			(1<<9)

#define SEPG_DB_SCHEMA__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_SCHEMA__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_SCHEMA__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_SCHEMA__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_SCHEMA__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_SCHEMA__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_SCHEMA__SEARCH				(1<<6)
#define SEPG_DB_SCHEMA__ADD_OBJECT			(1<<7)
#define SEPG_DB_SCHEMA__REMOVE_OBJECT		(1<<8)

#define SEPG_DB_SCHEMA_TEMP__CREATE			(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_SCHEMA_TEMP__DROP			(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_SCHEMA_TEMP__GETATTR		(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_SCHEMA_TEMP__SETATTR		(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_SCHEMA_TEMP__RELABELFROM	(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_SCHEMA_TEMP__RELABELTO		(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_SCHEMA_TEMP__SEARCH			(SEPG_DB_SCHEMA__SEARCH)
#define SEPG_DB_SCHEMA_TEMP__ADD_OBJECT		(SEPG_DB_SCHEMA__ADD_OBJECT)
#define SEPG_DB_SCHEMA_TEMP__REMOVE_OBJECT	(SEPG_DB_SCHEMA__REMOVE_OBJECT)

#define SEPG_DB_TABLE__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_TABLE__DROP					(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_TABLE__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_TABLE__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_TABLE__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_TABLE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_TABLE__SELECT				(1<<6)
#define SEPG_DB_TABLE__UPDATE				(1<<7)
#define SEPG_DB_TABLE__INSERT				(1<<8)
#define SEPG_DB_TABLE__DELETE				(1<<9)
#define SEPG_DB_TABLE__LOCK					(1<<10)
#define SEPG_DB_TABLE__REFERENCE			(1<<11)

#define SEPG_DB_SEQUENCE__CREATE			(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_SEQUENCE__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_SEQUENCE__GETATTR			(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_SEQUENCE__SETATTR			(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_SEQUENCE__RELABELFROM		(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_SEQUENCE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_SEQUENCE__GET_VALUE			(1<<6)
#define SEPG_DB_SEQUENCE__NEXT_VALUE		(1<<7)
#define SEPG_DB_SEQUENCE__SET_VALUE			(1<<8)

#define SEPG_DB_PROCEDURE__CREATE			(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_PROCEDURE__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_PROCEDURE__GETATTR			(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_PROCEDURE__SETATTR			(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_PROCEDURE__RELABELFROM		(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_PROCEDURE__RELABELTO		(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_PROCEDURE__EXECUTE			(1<<6)
#define SEPG_DB_PROCEDURE__ENTRYPOINT		(1<<7)
#define SEPG_DB_PROCEDURE__INSTALL			(1<<8)

#define SEPG_DB_COLUMN__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_COLUMN__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_COLUMN__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_COLUMN__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_COLUMN__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_COLUMN__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_COLUMN__SELECT				(1<<6)
#define SEPG_DB_COLUMN__UPDATE				(1<<7)
#define SEPG_DB_COLUMN__INSERT				(1<<8)
#define SEPG_DB_COLUMN__REFERENCE			(1<<9)

#define SEPG_DB_TUPLE__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_TUPLE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_TUPLE__SELECT				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_TUPLE__UPDATE				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_TUPLE__INSERT				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_TUPLE__DELETE				(SEPG_DB_DATABASE__DROP)

#define SEPG_DB_BLOB__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_BLOB__DROP					(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_BLOB__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_BLOB__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_BLOB__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_BLOB__RELABELTO				(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_BLOB__READ					(1<<6)
#define SEPG_DB_BLOB__WRITE					(1<<7)
#define SEPG_DB_BLOB__IMPORT				(1<<8)
#define SEPG_DB_BLOB__EXPORT				(1<<9)

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
sepgsqlCheckSchemaSearch(Oid namespace_oid);

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

/* hooks.c */
#define sepgsqlCheckDatabaseConnect(a)				(true)
#define sepgsqlCheckDatabaseSuperuser(a)			(true)
#define sepgsqlCheckSchemaSearch(a)					(true)
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
