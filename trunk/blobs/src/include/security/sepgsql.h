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

#ifdef HAVE_SELINUX

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

/* workaround for older libselinux */
#ifndef	DB_PROCEDURE__INSTALL
#define	DB_PROCEDURE__INSTALL		0x00000100UL
#endif

/*
 * An alias type of security id
 */
typedef Oid	sepgsql_sid_t;

/* GUC parameter to turn on/off SE-PostgreSQL */
extern bool sepostgresql_is_enabled;

/* GUC parameter to turn on/off Row-level controls */
extern bool sepostgresql_row_level;

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
sepgsqlClientCreate(sepgsql_sid_t tcontext, security_class_t tclass);

extern security_context_t
sepgsqlClientCreateLabel(sepgsql_sid_t tcontext, security_class_t tclass);

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
extern List *
sepgsqlAddEvalTable(List *selist, Oid relid, bool inh,
								 uint32 perms);
extern List *
sepgsqlAddEvalColumn(List *selist, Oid relid, bool inh,
								  AttrNumber attno, uint32 perms);
extern List *
sepgsqlAddEvalTriggerFunc(List *selist, Oid relid, int cmdType);

extern void
sepgsqlCheckSelinuxEvalItem(SelinuxEvalItem *seitem);

extern void
sepgsqlPostQueryRewrite(List *queryList);

extern void
sepgsqlExecutorStart(QueryDesc *queryDesc, int eflags);

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

extern void
sepgsqlCheckDatabaseSetParam(const char *name);

extern void
sepgsqlCheckDatabaseGetParam(const char *name);

extern void
sepgsqlCheckDatabaseInstallModule(const char *filename);

extern void
sepgsqlCheckDatabaseLoadModule(const char *filename);

extern bool
sepgsqlCheckProcedureExecute(Oid proc_oid);

extern void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *finfo, HeapTuple protup);

extern bool
sepgsqlCheckTableLock(Oid relid);

extern bool
sepgsqlCheckTableTruncate(Relation rel);

extern bool
sepgsqlCheckTupleSelectOnTrigger(TriggerData *tgdata);

extern void
sepgsqlCheckBlobDrop(HeapTuple lotup);

extern void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj);

extern void
sepgsqlCheckBlobWrite(LargeObjectDesc *lobj);

extern void
sepgsqlCheckBlobGetattr(LargeObjectDesc *lobj);

extern void
sepgsqlCheckBlobSetattr(LargeObjectDesc *lobj);

extern void
sepgsqlCheckBlobExport(LargeObjectDesc *lobj, int fdesc, const char *filename);

extern void
sepgsqlCheckBlobImport(LargeObjectDesc *lobj, int fdesc, const char *filename);

extern void
sepgsqlCheckBlobRelabel(HeapTuple oldtup, HeapTuple newtup);

// HeapTuple INSERT/UPDATE/DELETE
extern bool
sepgsqlExecScan(Relation rel, HeapTuple tuple, AclMode required, bool abort);

extern bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple newtup, bool internal);

extern bool
sepgsqlHeapTupleUpdate(Relation rel, HeapTuple oldtup, HeapTuple newtup, bool internal);

extern bool
sepgsqlHeapTupleDelete(Relation rel, HeapTuple oldtup, bool internal);

// COPY TO/FROM statement
extern void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom);

extern void
sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom);

extern bool
sepgsqlCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple);

/*
 * label.c : security label management
 */
extern bool
sepgsqlTupleDescHasSecLabel(Relation rel);

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
#define SEPGSQL_PERMS_USE			(1UL<<(N_ACL_RIGHTS+0))
#define SEPGSQL_PERMS_SELECT		(1UL<<(N_ACL_RIGHTS+1))
#define SEPGSQL_PERMS_INSERT		(1UL<<(N_ACL_RIGHTS+2))
#define SEPGSQL_PERMS_UPDATE		(1UL<<(N_ACL_RIGHTS+3))
#define SEPGSQL_PERMS_DELETE		(1UL<<(N_ACL_RIGHTS+4))
#define SEPGSQL_PERMS_RELABELFROM	(1UL<<(N_ACL_RIGHTS+5))
#define SEPGSQL_PERMS_RELABELTO		(1UL<<(N_ACL_RIGHTS+6))
#define SEPGSQL_PERMS_MASK			(~ACL_ALL_RIGHTS)

extern const char *
sepgsqlAuditName(Oid relid, HeapTuple tuple);

extern security_class_t
sepgsqlFileObjectClass(int fdesc);

extern security_class_t
sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple);

extern bool
sepgsqlCheckObjectPerms(Relation rel, HeapTuple tuple, HeapTuple newtup,
						uint32 required, bool abort);

extern void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple);

#else	/* HAVE_SELINUX */

// avc.c
#define sepgsqlShmemSize()						(0)
#define sepgsqlStartupWorkerProcess()			(0)
// checker.c
#define sepgsqlPostQueryRewrite(a)				do {} while(0)
#define sepgsqlExecutorStart(a,b)				do {} while(0)
// core.c
#define sepgsqlIsEnabled()						(false)
#define sepgsqlInitialize()						do {} while(0)
// hooks.c
#define sepgsqlCheckDatabaseAccess(a)			(true)
#define sepgsqlCheckDatabaseSetParam(a)			do {} while(0)
#define sepgsqlCheckDatabaseGetParam(a)			do {} while(0)
#define sepgsqlCheckDatabaseInstallModule(a)	do {} while(0)
#define sepgsqlCheckDatabaseLoadModule(a)		do {} while(0)
#define sepgsqlCheckProcedureExecute(a)			(true)
#define sepgsqlCheckProcedureEntrypoint(a,b)	do {} while(0)
#define sepgsqlCheckTableLock(a)				(true)
#define sepgsqlCheckTableTruncate(a)			(true)
#define sepgsqlCheckTupleSelectOnTrigger(a)		(true)
#define sepgsqlCheckBlobDrop(a)					do {} while(0)
#define sepgsqlCheckBlobRead(a)					do {} while(0)
#define sepgsqlCheckBlobWrite(a)				do {} while(0)
#define sepgsqlCheckBlobGetattr(a)				do {} while(0)
#define sepgsqlCheckBlobSetattr(a)				do {} while(0)
#define sepgsqlCheckBlobExport(a,b,c)			do {} while(0)
#define sepgsqlCheckBlobImport(a,b,c)			do {} while(0)
#define sepgsqlCheckBlobRelabel(a,b)			do {} while(0)

#define sepgsqlExecScan(a,b,c,d)				(true)
#define sepgsqlHeapTupleInsert(a,b,c)			(true)
#define sepgsqlHeapTupleUpdate(a,b,c,d)			(true)
#define sepgsqlHeapTupleDelete(a,b,c)			(true)

#define sepgsqlCopyTable(a,b,c)					do {} while(0)
#define sepgsqlCopyFile(a,b,c,d)				do {} while(0)
#define sepgsqlCopyToTuple(a,b,c)				(true)

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
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_mcstrans(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_get_range(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_user(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_role(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_type(PG_FUNCTION_ARGS);
extern Datum sepgsql_set_range(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
