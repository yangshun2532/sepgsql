/*
 * src/include/utils/sepgsql.h
 *    Headers of SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

#include "access/htup.h"
#include "executor/execdesc.h"
#include "fmgr.h"
#include "nodes/parsenodes.h"
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
 * avc.c : userspace access vector cache
 */
extern Size sepgsqlShmemSize(void);

extern bool sepgsqlGetExceptionMode(void);

extern bool sepgsqlSetExceptionMode(bool exception);

extern void sepgsqlAvcInit(void);

extern pid_t sepgsqlStartupWorkerProcess(void);

extern void sepgsqlAvcSwitchClient(void);

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
sepgsqlClientCreateSecid(Oid nrelid, Oid trelid, Oid tsecid,
						 security_class_t tclass);

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

extern bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, uint32 required, bool abort);

extern uint32
sepgsqlSetupTuplePerms(RangeTblEntry *rte);

extern bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal);

extern bool
sepgsqlHeapTupleUpdate(Relation rel, HeapTuple oldtup, HeapTuple newtup, bool internal);

extern bool
sepgsqlHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal);

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
 * hooks.c : test certain permissions
 */
extern bool
sepgsqlCheckDatabaseAccess(Oid database_oid);

extern bool
sepgsqlCheckDatabaseSuperuser(void);

extern bool
sepgsqlCheckSchemaSearch(Oid nsid);

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

extern bool
sepgsqlCheckProcedureExecute(Oid proc_oid);

extern void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *finfo, HeapTuple protup);

// Hint for optimizer
extern bool
sepgsqlAllowFunctionInlined(HeapTuple protup);

/*
 * label.c : security label management
 */
extern bool
sepgsqlTupleDescHasSecLabel(Relation rel);

extern void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple);

extern security_context_t
sepgsqlMetaSecurityLabel(void);

extern Oid
sepgsqlGivenDatabaseSecLabelIn(DefElem *defel);

extern Oid
sepgsqlGivenProcedureSecLabelIn(DefElem *defel);

extern Oid
sepgsqlGivenTableSecLabelIn(DefElem *defel);

extern Oid
sepgsqlGivenColumnSecLabelIn(DefElem *defel);

extern List *
sepgsqlGivenCreateStmtSecLabelIn(CreateStmt *stmt);

extern security_context_t
sepgsqlTransSecLabelIn(security_context_t seclabel);

extern security_context_t
sepgsqlTransSecLabelOut(security_context_t seclabel);

extern security_context_t
sepgsqlRawSecLabelIn(security_context_t seclabel);

extern security_context_t
sepgsqlRawSecLabelOut(security_context_t seclabel);

/*
 * perms.c : SELinux permission related stuff
 */
extern const char *
sepgsqlAuditName(Oid relid, HeapTuple tuple);

extern security_class_t
sepgsqlFileObjectClass(int fdesc);

extern security_class_t
sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple);

extern security_class_t
sepgsqlTransToExternalClass(security_class_t tclass_in);

extern void
sepgsqlTransToInternalPerms(security_class_t tclass_ex, struct av_decision *avd);

extern const char *
sepgsqlGetClassString(security_class_t tclass);

extern const char *
sepgsqlGetPermissionString(security_class_t tclass, access_vector_t av);

#else	/* HAVE_SELINUX */

/* avc.c */
#define sepgsqlShmemSize()						(0)
#define sepgsqlStartupWorkerProcess()			(0)
#define sepgsqlGetExceptionMode()				(0)
#define sepgsqlSetExceptionMode(a)				(0)
/* checker.c */
#define sepgsqlCheckRTEPerms(a)					do {} while(0)
#define sepgsqlCheckCopyTable(a,b,c)			do {} while(0)
#define sepgsqlCheckSelectInto(a)				do {} while(0)
#define sepgsqlSetupTuplePerms(a)				(0)
#define sepgsqlExecScan(a,b,c,d)				(true)
#define sepgsqlHeapTupleInsert(a,b,c)			(true)
#define sepgsqlHeapTupleUpdate(a,b,c,d)			(true)
#define sepgsqlHeapTupleDelete(a,b,c)			(true)
/* core.c */
#define sepgsqlIsEnabled()						(false)
#define sepgsqlInitialize()						do {} while(0)
// hooks.c
#define sepgsqlCheckDatabaseAccess(a)			(true)
#define sepgsqlCheckDatabaseSuperuser()			(true)
#define sepgsqlCheckSchemaSearch(a)				(true)
#define sepgsqlCheckTableLock(a)				do {} while(0)
#define sepgsqlCheckTableTruncate(a)			do {} while(0)
#define sepgsqlCheckTableReference(a,b,c)		do {} while(0)
#define sepgsqlCheckSequenceGetValue(a)			do {} while(0)
#define sepgsqlCheckSequenceNextValue(a)		do {} while(0)
#define sepgsqlCheckSequenceSetValue(a)			do {} while(0)
#define sepgsqlCheckProcedureExecute(a)			(true)
#define sepgsqlCheckProcedureEntrypoint(a,b)	do {} while(0)
#define sepgsqlAllowFunctionInlined(a)			(true)
// label.c
#define sepgsqlTupleDescHasSecLabel(a)			(false)
<<<<<<< .working
#define sepgsqlMetaSecurityLabel()				(NULL)
#define sepgsqlInputGivenSecLabel(a)			(InvalidOid)
#define sepgsqlInputGivenSecLabelRelation(a)	(NIL)
#define sepgsqlSecurityLabelTransIn(a)			(a)
#define sepgsqlSecurityLabelTransOut(a)			(a)
=======
#define sepgsqlGivenDatabaseSecLabelIn(a)		(InvalidOid)
#define sepgsqlGivenProcedureSecLabelIn(a)		(InvalidOid)
#define sepgsqlGivenTableSecLabelIn(a)			(InvalidOid)
#define sepgsqlGivenColumnSecLabelIn(a)			(InvalidOid)
#define sepgsqlGivenCreateStmtSecLabelIn(a)		(NIL)
#define sepgsqlTransSecLabelIn(a)				(a)
#define sepgsqlTransSecLabelOut(a)				(a)
#define sepgsqlRawSecLabelIn(a)					(a)
#define sepgsqlRawSecLabelOut(a)				(a)
>>>>>>> .merge-right.r1965

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
