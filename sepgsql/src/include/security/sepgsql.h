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
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

/* workaround for older libselinux */
#ifndef	DB_PROCEDURE__INSTALL
#define	DB_PROCEDURE__INSTALL		0x00000100UL
#endif

/*
 * In this version, SE-PostgreSQL uses text formed security
 * context, not an object identifier.
 */
typedef security_context_t sepgsql_sid_t;

/* GUC parameter to turn on/off SE-PostgreSQL */
extern bool sepostgresql_is_enabled;

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

// HeapTuple INSERT/UPDATE/DELETE
extern HeapTuple
sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple, bool internal);

extern void
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple tuple, bool internal);

extern void
sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid, bool internal);

// COPY TO/FROM statement
extern void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom);
extern void
sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom);

// Hint for optimizer
extern bool
sepgsqlAllowFunctionInlined(HeapTuple protup);

/*
 * label.c : security label management
 */
extern bool
HeapTupleHasSecLabel(Oid relid, HeapTuple tuple);

extern sepgsql_sid_t
HeapTupleGetSecLabel(Oid relid, HeapTuple tuple);

extern Datum
sepgsqlInputGivenSecLabel(DefElem *defel);

extern List *
sepgsqlInputGivenSecLabelRelation(CreateStmt *stmt);

extern void
sepgsqlSetDefaultSecLabel(Oid relid, Datum *values, bool *nulls, Datum given);

extern security_context_t
sepgsqlSecurityLabelTransIn(security_context_t label);

extern security_context_t
sepgsqlSecurityLabelTransOut(security_context_t label);

extern bool
sepgsqlCheckValidSecurityLabel(security_context_t label);

/*
 * perms.c : SE-PostgreSQL permission checks
 */
#define SEPGSQL_PERMS_USE			(1UL<<0)
#define SEPGSQL_PERMS_SELECT		(1UL<<1)
#define SEPGSQL_PERMS_INSERT		(1UL<<2)
#define SEPGSQL_PERMS_UPDATE		(1UL<<3)
#define SEPGSQL_PERMS_DELETE		(1UL<<4)
#define SEPGSQL_PERMS_RELABELFROM	(1UL<<5)
#define SEPGSQL_PERMS_RELABELTO		(1UL<<6)
#define SEPGSQL_PERMS_MASK			(0x0000007f)

extern const char *
sepgsqlAuditName(Oid relid, HeapTuple tuple);

extern security_class_t
sepgsqlFileObjectClass(int fdesc);

extern security_class_t
sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple);

extern bool
sepgsqlCheckObjectPerms(Relation rel, HeapTuple tuple, HeapTuple newtup,
						uint32 required, bool abort);

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

#define sepgsqlHeapTupleInsert(a,b,c)			(b)
#define sepgsqlHeapTupleUpdate(a,b,c,d)			do {} while(0)
#define sepgsqlHeapTupleDelete(a,b,c)			do {} while(0)

#define sepgsqlCopyTable(a,b,c)					do {} while(0)
#define sepgsqlCopyFile(a,b,c,d)				do {} while(0)

#define sepgsqlAllowFunctionInlined(a)			(true)

// label.c
#define sepgsqlInputGivenSecLabel(a)			(PointerGetDatum(NULL))
#define sepgsqlInputGivenSecLabelRelation(a)	(NIL)
#define sepgsqlSetDefaultSecLabel(a,b,c,d)		do {} while(0)

#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_mcstrans(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
