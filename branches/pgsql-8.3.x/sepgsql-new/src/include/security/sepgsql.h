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
#include "commands/trigger.h"
#include "executor/execdesc.h"
#include "fmgr.h"
#include "nodes/parsenodes.h"
#include "storage/large_object.h"
#include "utils/relcache.h"

typedef Oid		sepgsql_sid_t;

#ifdef HAVE_SELINUX

#include <selinux/selinux.h>

/* GUC parameter to turn on/off SE-PostgreSQL */
extern bool sepostgresql_is_enabled;

/* GUC parameter to turn on/off Row-level controls */
extern bool sepostgresql_row_level;

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
	SEPG_CLASS_DB_TABLE,
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

extern void sepgsqlAvcInit(void);

extern pid_t sepgsqlStartupWorkerProcess(void);

extern void sepgsqlAvcSwitchClient(void);

extern bool
sepgsqlClientHasPerms(sepgsql_sid_t tcontext,
					  security_class_t tclass,
					  access_vector_t required,
					  const char *audit_name, bool abort);
extern sepgsql_sid_t
sepgsqlClientCreate(sepgsql_sid_t tcontext,
					security_class_t tclass);

extern security_context_t
sepgsqlClientCreateLabel(sepgsql_sid_t tcontext,
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
 * checker.c : pick up all the appeared objects and apply checks
 */
extern void
sepgsqlCheckRTEPerms(RangeTblEntry *rte);

extern void
sepgsqlCheckCopyTable(Relation rel, List *attnumlist, bool is_from);

extern void
sepgsqlCheckSelectInto(Oid relaionId);

extern bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, AclMode required, bool abort);

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
sepgsqlGetUnlabeledLabel(void);

extern security_context_t
sepgsqlGetDatabaseLabel(void);

extern sepgsql_sid_t
sepgsqlGetDatabaseSid(void);

extern security_context_t
sepgsqlSwitchClient(security_context_t new_client);

extern bool
sepgsqlIsEnabled(void);

extern void
sepgsqlInitialize(void);

/*
 * hooks.c : security hooks
 */
extern bool
sepgsqlCheckDatabaseAccess(Oid db_oid);

extern bool
sepgsqlCheckDatabaseSuperuser(void);

extern void
sepgsqlCheckDatabaseInstallModule(const char *filename);

extern void
sepgsqlCheckDatabaseLoadModule(const char *filename);

extern bool
sepgsqlCheckTableLock(Oid table_oid);

extern bool
sepgsqlCheckTableTruncate(Relation rel);

extern bool
sepgsqlCheckProcedureExecute(Oid proc_oid);

extern void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *finfo, HeapTuple protup);

extern void
sepgsqlCheckProcedureInstall(Relation rel, HeapTuple newtup, HeapTuple oldtup);

extern void
sepgsqlCheckBlobDrop(HeapTuple lotup);

extern void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj);

extern void
sepgsqlCheckBlobWrite(LargeObjectDesc *lobj);

extern void
sepgsqlCheckBlobGetattr(HeapTuple tuple);

extern void
sepgsqlCheckBlobSetattr(HeapTuple tuple);

extern void
sepgsqlCheckBlobExport(LargeObjectDesc *lobj, int fdesc, const char *filename);

extern void
sepgsqlCheckBlobImport(LargeObjectDesc *lobj, int fdesc, const char *filename);

extern void
sepgsqlCheckBlobRelabel(HeapTuple oldtup, HeapTuple newtup);

extern void
sepgsqlCheckFileRead(int fdesc, const char *filename);

extern void
sepgsqlCheckFileWrite(int fdesc, const char *filename);

extern bool
sepgsqlAllowFunctionInlined(HeapTuple protup);

/*
 * label.c : security label management
 */
extern bool
sepgsqlTupleDescHasSecLabel(Relation rel);

extern void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple);

extern char *
sepgsqlMetaSecurityLabel(void);

extern sepgsql_sid_t
sepgsqlInputGivenSecLabel(DefElem *defel);

extern List *
sepgsqlInputGivenSecLabelRelation(CreateStmt *stmt);

extern security_context_t
sepgsqlSecurityLabelTransIn(security_context_t label);

extern security_context_t
sepgsqlSecurityLabelTransOut(security_context_t label);

extern bool
sepgsqlCheckValidSecurityLabel(security_context_t label);

/*
 * perms.c : SE-PostgreSQL permission checks
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

extern bool
sepgsqlCheckObjectPerms(Relation rel, HeapTuple tuple,
                        access_vector_t required, bool abort);

#else	/* HAVE_SELINUX */

// avc.c
#define sepgsqlShmemSize()						(0)
#define sepgsqlStartupWorkerProcess()			(0)
// checker.c
#define sepgsqlCheckRTEPerms(a)					do {} while(0)
#define sepgsqlCheckSelectInto(a)				do {} while(0)
#define sepgsqlExecScan(a,b,c,d)				(true)
#define sepgsqlHeapTupleInsert(a,b,c)			(true)
#define sepgsqlHeapTupleUpdate(a,b,c,d)			(true)
#define sepgsqlHeapTupleDelete(a,b,c)			(true)
// core.c
#define sepgsqlIsEnabled()						(false)
#define sepgsqlInitialize()						do {} while(0)
// hooks.c
#define sepgsqlCheckDatabaseAccess(a)			(true)
#define sepgsqlCheckDatabaseSuperuser()			(true)
#define sepgsqlCheckDatabaseInstallModule(a)	do {} while(0)
#define sepgsqlCheckDatabaseLoadModule(a)		do {} while(0)
#define sepgsqlCheckTableLock(a)				(true)
#define sepgsqlCheckTableTruncate(a)			(true)
#define sepgsqlCheckProcedureExecute(a)			(true)
#define sepgsqlCheckProcedureEntrypoint(a,b)	do {} while(0)
#define sepgsqlCheckBlobDrop(a)					do {} while(0)
#define sepgsqlCheckBlobRead(a)					do {} while(0)
#define sepgsqlCheckBlobWrite(a)				do {} while(0)
#define sepgsqlCheckBlobGetattr(a)				do {} while(0)
#define sepgsqlCheckBlobSetattr(a)				do {} while(0)
#define sepgsqlCheckBlobExport(a,b,c)			do {} while(0)
#define sepgsqlCheckBlobImport(a,b,c)			do {} while(0)
#define sepgsqlCheckBlobRelabel(a,b)			do {} while(0)
#define sepgsqlCheckFileRead(a,b)				do {} while(0)
#define sepgsqlCheckFileWrite(a,b)				do {} while(0)
#define sepgsqlAllowFunctionInlined(a)			(true)
// label.c
#define sepgsqlTupleDescHasSecLabel(a)			(false)
#define sepgsqlMetaSecurityLabel()				(NULL)
#define sepgsqlInputGivenSecLabel(a)			(InvalidOid)
#define sepgsqlInputGivenSecLabelRelation(a)	(NIL)
#define sepgsqlSecurityLabelTransIn(a)			(a)
#define sepgsqlSecurityLabelTransOut(a)			(a)
#define sepgsqlCheckValidSecurityLabel(a)		(false)

#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_getservcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_range(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_range(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
