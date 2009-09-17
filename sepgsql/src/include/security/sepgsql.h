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
#include "storage/large_object.h"
#include "utils/relcache.h"

#ifdef HAVE_SELINUX

#include <selinux/selinux.h>

/* GUC parameter to turn on/off SE-PostgreSQL */
extern bool sepostgresql_is_enabled;

/* GUC parameter to turn on/off Row-level controls */
extern bool sepostgresql_row_level;

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
#define SEPG_DB_SCHEMA__ADD_NAME			(1<<7)
#define SEPG_DB_SCHEMA__REMOVE_NAME			(1<<8)

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
#define SEPG_DB_PROCEDURE__UNTRUSTED		(1<<9)

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
 * sepgsql_sid_t : alternative representation of security context
 */
typedef struct {
	Oid		relid;
	Oid		secid;
} sepgsql_sid_t;

#define SidIsValid(sid)		(OidIsValid((sid).relid) && OidIsValid((sid).secid))

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

extern Size sepgsqlShmemSize(void);
extern void sepgsqlAvcInitialize(void);

extern bool sepgsqlGetEnforce(void);
extern int  sepgsqlSetEnforce(int new_mode);
extern void sepgsqlAvcReset(void);
extern void sepgsqlAvcSwitchClient(const char *scontext);

extern bool
sepgsqlClientHasPerms(sepgsql_sid_t tsid,
					  uint16 tclass, uint32 required,
					  const char *audit_name, bool abort);
extern sepgsql_sid_t
sepgsqlClientCreateSecid(sepgsql_sid_t tsid, uint16 tclass, Oid nrelid);

extern security_context_t
sepgsqlClientCreateLabel(sepgsql_sid_t tsid, uint16 tclass);

extern bool
sepgsqlComputePerms(security_context_t scontext,
					security_context_t tcontext,
					uint16 tclass, uint32 required,
					const char *audit_name, bool abort);

extern security_context_t
sepgsqlComputeCreate(security_context_t scontext,
					 security_context_t tcontext,
					 uint16 tclass);

extern pid_t sepgsqlStartupWorkerProcess(void);

/*
 * bridge.c : new style security hooks
 */
/* pg_database */
extern Oid
sepgsql_database_create(const char *datName, DefElem *newLabel);
extern void
sepgsql_database_alter(Oid datOid);
extern void
sepgsql_database_drop(Oid datOid);
extern Oid
sepgsql_database_relabel(Oid datOid, DefElem *newLabel);
extern void
sepgsql_database_grant(Oid datOid);
extern void
sepgsql_database_access(Oid datOid);
extern bool
sepgsql_database_superuser(Oid datOid);
extern void
sepgsql_database_load_module(Oid datOid, const char *filename);

/* pg_namespace */
extern Oid
sepgsql_schema_create(const char *nspName, bool isTemp, DefElem *newLabel);
extern void
sepgsql_schema_alter(Oid nspOid);
extern void
sepgsql_schema_drop(Oid nspOid);
extern Oid
sepgsql_schema_relabel(Oid nspOid, DefElem *newLabel);
extern void
sepgsql_schema_grant(Oid nspOid);
extern bool
sepgsql_schema_search(Oid nspOid, bool abort);

/* pg_proc */
extern Oid
sepgsql_proc_create(const char *procName, Oid procOid,
					Oid nspOid, Oid langOid, DefElem *newLabel);
extern void
sepgsql_proc_alter(Oid procOid, const char *newName, Oid newNsp);
extern void
sepgsql_proc_drop(Oid procOid);
extern Oid
sepgsql_proc_relabel(Oid procOid, DefElem *newLabel);
extern void
sepgsql_proc_grant(Oid procOid);
extern void
sepgsql_proc_execute(Oid procOid);
extern bool
sepgsql_proc_hint_inlined(HeapTuple protup);
extern void
sepgsql_proc_entrypoint(FmgrInfo *flinfo, HeapTuple protup);

/* pg_cast */
extern Oid
sepgsql_cast_create(Oid sourceTypOid, Oid targetTypOid, Oid funcOid);
extern void
sepgsql_cast_drop(Oid castOid);

/* pg_opclass */
extern Oid
sepgsql_opclass_create(const char *opcName, Oid nspOid);
extern void
sepgsql_opclass_alter(Oid opcOid, const char *newName);
extern void
sepgsql_opclass_drop(Oid opcOid);

/* pg_opfamily */
extern Oid
sepgsql_opfamily_create(const char *opfName, Oid nspOid);
extern void
sepgsql_opfamily_alter(Oid opfOid, const char *newName);
extern void
sepgsql_opfamily_drop(Oid opfOid);
extern void
sepgsql_opfamily_add_operator(Oid opfOid, Oid operOid);
extern void
sepgsql_opfamily_add_procedure(Oid opfOid, Oid procOid);

/* pg_operator */
extern Oid
sepgsql_operator_create(const char *oprName, Oid oprOid, Oid nspOid,
						Oid codeFn, Oid restFn, Oid joinFn);
extern void
sepgsql_operator_alter(Oid oprOid);
extern void
sepgsql_operator_drop(Oid oprOid);

/* pg_type */
extern Oid
sepgsql_type_create(const char *typName, Oid typOid, Oid nspOid,
					Oid inputProc, Oid outputProc, Oid recvProc, Oid sendProc,
					Oid modinProc, Oid modoutProc, Oid analyzeProc);
extern void
sepgsql_type_alter(Oid typOid, const char *newName, Oid newNsp);
extern void
sepgsql_type_drop(Oid typOid);
/* misc objects */
extern void
sepgsql_sysobj_drop(const ObjectAddress *object);

/*
 * checker.c : check permission on given queries
 */
extern void
sepgsqlCheckRTEPerms(RangeTblEntry *rte);

extern void
sepgsqlCheckCopyTable(Relation rel, List *attnumlist, bool is_from);

extern void
sepgsqlCheckSelectInto(Oid relaionId);

extern bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, uint32 required, bool abort);

extern uint32
sepgsqlSetupTuplePerms(RangeTblEntry *rte);

extern void
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal);

extern void
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup);

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
sepgsqlCheckSequenceGetValue(Oid seqOid);
extern void
sepgsqlCheckSequenceNextValue(Oid seqOid);
extern void
sepgsqlCheckSequenceSetValue(Oid seqOid);

extern Oid
sepgsqlCheckColumnCreate(Oid relOid, const char *attname, DefElem *newLabel);
extern void
sepgsqlCheckColumnDrop(Oid relOid, AttrNumber attno);
extern void
sepgsqlCheckColumnSetattr(Oid relOid, AttrNumber attno);
extern Oid
sepgsqlCheckColumnRelabel(Oid relOid, AttrNumber attno, DefElem *newLabel);

extern Oid
sepgsqlCheckProcedureCreate(const char *procName, Oid procOid,
                            Oid procNsp, Oid procLang, DefElem *newLabel);
extern void
sepgsqlCheckProcedureDrop(Oid procOid);
extern void
sepgsqlCheckProcedureSetattr(Oid procOid);
extern Oid
sepgsqlCheckProcedureRelabel(Oid procOid, DefElem *newLabel);
extern void
sepgsqlCheckProcedureExecute(Oid procOid);
extern void
sepgsqlCheckProcedureInstall(Oid procOid);
extern bool
sepgsqlHintProcedureInlined(HeapTuple protup);
extern void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *flinfo, HeapTuple protup);

extern void
sepgsqlCheckBlobCreate(Relation rel, HeapTuple lotup);
extern void
sepgsqlCheckBlobDrop(Relation rel, HeapTuple lotup);
extern void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj);
extern void
sepgsqlCheckBlobWrite(LargeObjectDesc *lobj);
extern void
sepgsqlCheckBlobGetattr(HeapTuple tuple);
extern void
sepgsqlCheckBlobSetattr(HeapTuple tuple);
extern void
sepgsqlCheckBlobExport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename);
extern void
sepgsqlCheckBlobImport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename);
extern void
sepgsqlCheckBlobRelabel(HeapTuple oldtup, HeapTuple newtup);

extern void
sepgsqlCheckFileRead(int fdesc, const char *filename);
extern void
sepgsqlCheckFileWrite(int fdesc, const char *filename);

extern Oid
sepgsqlCheckSysobjCreate(Oid relid, const char *auditName);
extern void
sepgsqlCheckSysobjGetattr(Oid relid, Oid secid, const char *auditName);
extern void
sepgsqlCheckSysobjSetattr(Oid relid, Oid secid, const char *auditName);
extern void
sepgsqlCheckSysobjDrop(const ObjectAddress *object);

/*
 * label.c : security label management
 */
extern bool
sepgsqlTupleDescHasSecid(Oid relid, char relkind);

extern void sepgsqlSetDefaultSecid(Relation rel, HeapTuple tuple);
extern sepgsql_sid_t sepgsqlGetDefaultDatabaseSecid(void);
extern sepgsql_sid_t sepgsqlGetDefaultSchemaSecid(Oid database_oid);
extern sepgsql_sid_t sepgsqlGetDefaultSchemaTempSecid(Oid database_oid);
extern sepgsql_sid_t sepgsqlGetDefaultTableSecid(Oid namespace_oid);
extern sepgsql_sid_t sepgsqlGetDefaultSequenceSecid(Oid namespace_oid);
extern sepgsql_sid_t sepgsqlGetDefaultProcedureSecid(Oid namespace_oid);
extern sepgsql_sid_t sepgsqlGetDefaultColumnSecid(Oid table_oid);
extern sepgsql_sid_t sepgsqlGetDefaultTupleSecid(Oid table_oid);
extern sepgsql_sid_t sepgsqlGetDefaultBlobSecid(Oid database_oid);

extern Oid *sepgsqlCreateTableColumns(CreateStmt *stmt,
									  const char *relname, Oid namespace_oid,
									  TupleDesc tupdesc, char relkind);
extern Oid *sepgsqlCopyTableColumns(Relation source);

extern sepgsql_sid_t
sepgsqlGetTupleSecid(Oid tableOid, HeapTuple tuple, uint16 *tclass);
extern sepgsql_sid_t
sepgsqlGetSysobjSecid(Oid tableOid, Oid objectId, int32 objsubId, uint16 *tclass);

extern char *sepgsqlTransSecLabelIn(char *seclabel);
extern char *sepgsqlTransSecLabelOut(char *seclabel);
extern char *sepgsqlRawSecLabelIn(char *seclabel);
extern char *sepgsqlRawSecLabelOut(char *seclabel);
extern char *sepgsqlSysattSecLabelOut(Oid relid, HeapTuple tuple);

/*
 * perms.c : SELinux permission related stuff
 */
extern uint16 sepgsqlFileObjectClass(int fdesc);

extern uint16 sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple);

extern security_class_t sepgsqlTransToExternalClass(uint16 tclass_in);

extern void sepgsqlTransToInternalPerms(security_class_t tclass_ex,
										struct av_decision *avd);
extern const char *sepgsqlGetClassString(uint16 tclass);
extern const char *sepgsqlGetPermString(uint16 tclass, uint32 permission);

#else	/* HAVE_SELINUX */

/* avc.c */
#define sepgsqlShmemSize()						(0)
#define sepgsqlStartupWorkerProcess()			(0)

/* checker.c */
#define sepgsqlCheckRTEPerms(a)					do {} while(0)
#define sepgsqlCheckCopyTable(a,b,c)			do {} while(0)
#define sepgsqlCheckSelectInto(a)				do {} while(0)
#define sepgsqlExecScan(a,b,c)					(true)
#define sepgsqlSetupTuplePerms(a)				(0)
#define sepgsqlHeapTupleInsert(a,b,c)			do {} while(0)
#define sepgsqlHeapTupleUpdate(a,b,c)			do {} while(0)

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
#define sepgsqlCheckDatabaseLoadModule(a)		do {} while(0)

#define sepgsqlCheckSchemaCreate(a,b,c)			(InvalidOid)
#define sepgsqlCheckSchemaDrop(a)				do {} while(0)
#define sepgsqlCheckSchemaSetattr(a)			do {} while(0)
#define sepgsqlCheckSchemaRelabel(a,b)			(InvalidOid)
#define sepgsqlCheckSchemaAddName(a)			do {} while(0)
#define sepgsqlCheckSchemaRemoveName(a)			do {} while(0)
#define sepgsqlCheckSchemaSearch(a,b)			(true)

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

#define sepgsqlCheckProcedureCreate(a,b,c,d)	(InvalidOid)
#define sepgsqlCheckProcedureDrop(a)			do {} while(0)
#define sepgsqlCheckProcedureSetattr(a)			do {} while(0)
#define sepgsqlCheckProcedureRelabel(a,b)		(InvalidOid)
#define sepgsqlCheckProcedureExecute(a)			(true)
#define sepgsqlCheckProcedureInstall(a)			do {} while(0)
#define sepgsqlHintProcedureInlined(a)			(true)
#define sepgsqlCheckProcedureEntrypoint(a,b)	do {} while(0)

#define sepgsqlCheckBlobCreate(a,b)				do {} while(0)
#define sepgsqlCheckBlobDrop(a,b)				do {} while(0)
#define sepgsqlCheckBlobRead(a)					do {} while(0)
#define sepgsqlCheckBlobWrite(a)				do {} while(0)
#define sepgsqlCheckBlobGetattr(a)				do {} while(0)
#define sepgsqlCheckBlobSetattr(a)				do {} while(0)
#define sepgsqlCheckBlobExport(a,b,c)			do {} while(0)
#define sepgsqlCheckBlobImport(a,b,c)			do {} while(0)
#define sepgsqlCheckBlobRelabel(a,b)			do {} while(0)
#define sepgsqlCheckFileRead(a,b)				do {} while(0)
#define sepgsqlCheckFileWrite(a,b)				do {} while(0)

#define sepgsqlCheckSysobjCreate(a,b)			(InvalidOid)
#define sepgsqlCheckSysobjGetattr(a,b,c)		do {} while(0)
#define sepgsqlCheckSysobjSetattr(a,b,c)		do {} while(0)
#define sepgsqlCheckSysobjDrop(a)				do {} while(0)

/* label.c */
#define sepgsqlTupleDescHasSecLabel(a,b)		(false)
#define sepgsqlSetDefaultSecLabel(a,b)			do {} while(0)
#define sepgsqlCreateTableColumns(a,b,c,d,e)	(NULL)
#define sepgsqlCopyTableColumns(a)				(NULL)
#define sepgsqlMetaSecurityLabel()				(NULL)
#define sepgsqlTransSecLabelIn(a)				(a)
#define sepgsqlTransSecLabelOut(a)				(a)
#define sepgsqlRawSecLabelIn(a)					(a)
#define sepgsqlRawSecLabelOut(a)				(a)

#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_range(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_range(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
