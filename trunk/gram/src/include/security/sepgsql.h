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
#include "catalog/dependency.h"
#include "executor/execdesc.h"
#include "fmgr.h"
#include "nodes/parsenodes.h"
#include "utils/relcache.h"

#ifdef HAVE_SELINUX

#include <selinux/selinux.h>

/* GUC parameter to turn on/off SE-PostgreSQL */
extern bool sepostgresql_is_enabled;

/* GUC parameter to turn on/off mcstrans */
extern bool sepostgresql_use_mcstrans;

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
#define SEPG_DB_DATABASE__ACCESS			(1<<6)
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

/* Hook for plugin to record audit logs  */
typedef void (*sepgsqlAvcAuditHook_t)(const char *scontext, const char *tcontext,
									  const char *tclass, const char *av_perms,
									  bool denied, const char *audit_name);
extern PGDLLIMPORT sepgsqlAvcAuditHook_t sepgsqlAvcAuditHook;

extern Size	sepgsqlShmemSize(void);
extern int	sepgsqlSetLocalEnforce(int mode);
extern bool	sepgsqlGetEnforce(void);
extern void	sepgsqlAvcInit(void);
extern void	sepgsqlAvcSwitchClient(void);
extern pid_t sepgsqlStartupWorkerProcess(void);

extern bool
sepgsqlClientHasPermsTup(Oid relid, HeapTuple tuple,
						 security_class_t tclass,
						 access_vector_t required, bool abort);
extern bool
sepgsqlClientHasPermsSid(Oid relid, Oid secid,
						 security_class_t tclass,
						 access_vector_t required,
						 const char *audit_name, bool abort);
extern Oid
sepgsqlClientCreateSecid(Oid trelid, Oid tsecid,
						 security_class_t tclass, Oid nrelid);

extern security_context_t
sepgsqlClientCreateLabel(Oid trelid, Oid tsecid,
						 security_class_t tclass);

extern bool
sepgsqlComputePerms(security_context_t scontext,
					security_context_t tcontext,
					security_class_t tclass,
					access_vector_t required,
					const char *audit_name, bool abort);

extern security_context_t
sepgsqlComputeCreate(security_context_t scontext,
					 security_context_t tcontext,
					 security_class_t tclass);

/*
 * checker.c : check permission on given queries
 */
extern void
sepgsqlCheckRTEPerms(RangeTblEntry *rte);

extern void
sepgsqlCheckCopyTable(Relation rel, List *attnumlist, bool is_from);

extern void
sepgsqlCheckSelectInto(Oid relaionId);

/*
 * core.c : core facilities
 */
extern security_context_t
sepgsqlGetServerLabel(void);

extern security_context_t
sepgsqlGetClientLabel(void);

extern security_context_t
sepgsqlSwitchClient(security_context_t new_client);

extern bool
sepgsqlIsEnabled(void);

extern void
sepgsqlInitialize(void);

/*
 * hooks.c : routines to check certain permissions
 */
extern Oid
sepgsqlCheckDatabaseCreate(const char *datname, DefElem *new_label);
extern void
sepgsqlCheckDatabaseDrop(Oid database_oid);
extern void
sepgsqlCheckDatabaseSetattr(Oid database_oid);
extern Oid
sepgsqlCheckDatabaseRelabel(Oid database_oid, DefElem *new_label);
extern bool
sepgsqlCheckDatabaseAccess(Oid database_oid);
extern bool
sepgsqlCheckDatabaseSuperuser(void);

extern Oid
sepgsqlCheckSchemaCreate(const char *nspname, DefElem *new_label, bool temp_schame);
extern void
sepgsqlCheckSchemaDrop(Oid namespace_oid);
extern void
sepgsqlCheckSchemaSetattr(Oid namespace_oid);
extern Oid
sepgsqlCheckSchemaRelabel(Oid namespace_oid, DefElem *new_label);
extern bool
sepgsqlCheckSchemaSearch(Oid nsid);

extern void
sepgsqlCheckTableDrop(Oid table_oid);
extern void
sepgsqlCheckTableSetattr(Oid table_oid);
extern Oid
sepgsqlCheckTableRelabel(Oid table_oid, DefElem *new_label);
extern void
sepgsqlCheckTableLock(Oid table_oid);
extern void
sepgsqlCheckTableTruncate(Relation rel);
extern void
sepgsqlCheckTableReference(Relation rel, int16 *attnums, int natts);

extern void
sepgsqlCheckSequenceGetValue(Oid seqid);
extern void
sepgsqlCheckSequenceNextValue(Oid seqid);
extern void
sepgsqlCheckSequenceSetValue(Oid seqid);

extern Oid
sepgsqlCheckColumnCreate(Oid table_oid, const char *attname, DefElem *new_label);
extern void
sepgsqlCheckColumnDrop(Oid table_oid, AttrNumber attno);
extern void
sepgsqlCheckColumnSetattr(Oid table_oid, AttrNumber attno);
extern Oid
sepgsqlCheckColumnRelabel(Oid table_oid, AttrNumber attno, DefElem *new_label);

extern Oid
sepgsqlCheckProcedureCreate(const char *proname, Oid namespace_oid, DefElem *new_label);
extern void
sepgsqlCheckProcedureDrop(Oid proc_oid);
extern void
sepgsqlCheckProcedureSetattr(Oid proc_oid);
extern Oid
sepgsqlCheckProcedureRelabel(Oid proc_oid, DefElem *new_label);
extern bool
sepgsqlCheckProcedureExecute(Oid proc_oid);
extern void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *finfo, HeapTuple protup);

void
sepgsqlCheckObjectDrop(const ObjectAddress *object);

/* optimizar hints */
extern bool
sepgsqlAllowFunctionInlined(HeapTuple protup);

/*
 * label.c : security label management
 */
extern bool
sepgsqlTupleDescHasSecLabel(Oid relid, char relkind);
extern void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple);

extern Oid sepgsqlGetDefaultDatabaseSecLabel(void);
extern Oid sepgsqlGetDefaultSchemaSecLabel(Oid database_oid);
extern Oid sepgsqlGetDefaultSchemaTempSecLabel(Oid database_oid);
extern Oid sepgsqlGetDefaultTableSecLabel(Oid namespace_oid);
extern Oid sepgsqlGetDefaultSequenceSecLabel(Oid namespace_oid);
extern Oid sepgsqlGetDefaultProcedureSecLabel(Oid namespace_oid);
extern Oid sepgsqlGetDefaultColumnSecLabel(Oid table_oid);
extern Oid sepgsqlGetDefaultTupleSecLabel(Oid table_oid);

extern Oid *sepgsqlCreateTableColumns(CreateStmt *stmt,
									  const char *relname, Oid namespace_oid,
									  TupleDesc tupdesc, char relkind);
extern Oid *sepgsqlCopyTableColumns(Relation source);

extern char *sepgsqlTransSecLabelIn(char *seclabel);
extern char *sepgsqlTransSecLabelOut(char *seclabel);
extern char *sepgsqlRawSecLabelIn(char *seclabel);
extern char *sepgsqlRawSecLabelOut(char *seclabel);

/*
 * perms.c : SELinux permission related stuff
 */
extern const char *sepgsqlAuditName(Oid relid, HeapTuple tuple);

extern security_class_t sepgsqlFileObjectClass(int fdesc);

extern security_class_t sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple);

extern security_class_t sepgsqlTransToExternalClass(security_class_t tclass_in);

extern void sepgsqlTransToInternalPerms(security_class_t tclass_ex,
										struct av_decision *avd);
extern const char *sepgsqlGetClassString(security_class_t tclass);
extern const char *sepgsqlGetPermissionString(security_class_t tclass,
											  access_vector_t av);

#else	/* HAVE_SELINUX */

/* avc.c */
#define sepgsqlShmemSize()						(0)
#define sepgsqlSetLocalEnforce(a)				(0)
#define sepgsqlStartupWorkerProcess()			(0)

/* checker.c */
#define sepgsqlCheckRTEPerms(a)					do {} while(0)
#define sepgsqlCheckCopyTable(a,b,c)			do {} while(0)
#define sepgsqlCheckSelectInto(a)				do {} while(0)

/* core.c */
#define sepgsqlIsEnabled()						(false)
#define sepgsqlInitialize()						do {} while(0)

/* hooks.c */
#define sepgsqlCheckDatabaseCreate(a,b)			(InvalidOid)
#define sepgsqlCheckDatabaseDrop(a)				do {} while(0)
#define sepgsqlCheckDatabaseSetattr(a)			do {} while(0)
#define sepgsqlCheckDatabaseRelabel(a,b)		(InvalidOid)
#define sepgsqlCheckDatabaseAccess(a)			(true)
#define sepgsqlCheckDatabaseSuperuser()			(true)

#define sepgsqlCheckSchemaCreate(a,b,c)			(InvalidOid)
#define sepgsqlCheckSchemaDrop(a)				do {} while(0)
#define sepgsqlCheckSchemaSetattr(a)			do {} while(0)
#define sepgsqlCheckSchemaRelabel(a,b)			(InvalidOid)
#define sepgsqlCheckSchemaSearch(a)				(true)

#define sepgsqlCheckTableDrop(a)				do {} while(0)
#define sepgsqlCheckTableSetattr(a)				do {} while(0)
#define sepgsqlCheckTableRelabel(a,b)			(InvalidOid)
#define sepgsqlCheckTableLock(a)				do {} while(0)
#define sepgsqlCheckTableTruncate(a)			do {} while(0)
#define sepgsqlCheckTableReference(a,b,c)		do {} while(0)

#define sepgsqlCheckSequenceGetValue(a)			do {} while(0)
#define sepgsqlCheckSequenceNextValue(a)		do {} while(0)
#define sepgsqlCheckSequenceSetValue(a)			do {} while(0)

#define sepgsqlCheckColumnCreate(a,b,c)			(InvalidOid)
#define sepgsqlCheckColumnDrop(a,b)				do {} while(0)
#define sepgsqlCheckColumnSetattr(a,b)			do {} while(0)
#define sepgsqlCheckColumnRelabel(a,b,c)		(InvalidOid)

#define sepgsqlCheckProcedureCreate(a,b,c)		(InvalidOid)
#define sepgsqlCheckProcedureDrop(a)			do {} while(0)
#define sepgsqlCheckProcedureSetattr(a)			do {} while(0)
#define sepgsqlCheckProcedureRelabel(a,b)		(InvalidOid)
#define sepgsqlCheckProcedureExecute(a)			(true)
#define sepgsqlCheckProcedureEntrypoint(a,b)	do {} while(0)

#define sepgsqlCheckObjectDrop(a)				do {} while(0)

#define sepgsqlAllowFunctionInlined(a)			(true)

/* label.c */
#define sepgsqlTupleDescHasSecLabel(a,b)		(false)
#define sepgsqlSetDefaultSecLabel(a,b)			do {} while(0)
#define sepgsqlCreateTableColumns(a,b,c,d,e)	(NULL)
#define sepgsqlCopyTableColumns(a)				(NULL)
#define sepgsqlTransSecLabelIn(a)				(a)
#define sepgsqlTransSecLabelOut(a)				(a)
#define sepgsqlRawSecLabelIn(a)					(a)
#define sepgsqlRawSecLabelOut(a)				(a)

#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
