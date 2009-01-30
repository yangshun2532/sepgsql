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

/* workaround for older av_permissions.h */
#ifndef	DB_PROCEDURE__INSTALL
#define	DB_PROCEDURE__INSTALL		0x00000100UL
#endif

/* GUC parameter */
extern bool sepostgresql_is_enabled;

/*
 * analyze.c : Query structure analyzer
 */
extern List *sepgsqlAddEvalTable(List *selist, Oid relid, bool inh,
								 uint32 perms);
extern List *sepgsqlAddEvalColumn(List *selist, Oid relid, bool inh,
								  AttrNumber attno, uint32 perms);
extern List *sepgsqlAddEvalTriggerFunc(List *selist, Oid relid, int cmdType);

extern void sepgsqlCheckSelinuxEvalItem(SelinuxEvalItem *seitem);

extern void sepgsqlPostQueryRewrite(List *queryList);

extern void sepgsqlExecutorStart(QueryDesc *queryDesc, int eflags);

/*
 * avc.c : userspace access vector cache
 */
extern Size sepgsqlShmemSize(void);

extern void sepgsqlAvcInit(void);

extern pid_t sepgsqlStartupWorkerProcess(void);

extern void sepgsqlAvcSwitchClientLabel(void);

extern bool
sepgsqlClientHasPerms(Oid tsid, security_class_t tclass,
					  access_vector_t perms,
					  const char *audit_name, bool abort);
extern Oid
sepgsqlClientCreateSid(Oid tsid, security_class_t tclass);

extern security_context_t
sepgsqlClientCreateLabel(Oid tsid, security_class_t tclass);

extern bool
sepgsqlComputePerms(security_context_t scontext,
					security_context_t tcontext,
					security_class_t tclass,
					access_vector_t perms, const char *audit_name);

extern security_context_t
sepgsqlComputeCreateLabel(security_context_t scontext,
						  security_context_t tcontext,
						  security_class_t tclass);

/*
 * core.c : core facilities
 */
extern security_context_t sepgsqlGetServerLabel(void);

extern security_context_t sepgsqlGetClientLabel(void);

extern security_context_t sepgsqlSwitchClientLabel(security_context_t new_label);

extern security_context_t sepgsqlGetUnlabeledLabel(void);

extern security_context_t sepgsqlGetDatabaseLabel(void);

extern Oid	sepgsqlGetDatabaseSid(void);

extern bool	sepgsqlIsEnabled(void);

extern void sepgsqlInitialize(void);

/*
 * hooks.c : security hooks
 */
extern bool sepgsqlDatabaseAccess(Oid db_oid);

extern void sepgsqlDatabaseSetParam(const char *name);

extern void sepgsqlDatabaseGetParam(const char *name);

extern void sepgsqlDatabaseInstallModule(const char *filename);

extern void sepgsqlDatabaseLoadModule(const char *filename);

extern bool sepgsqlProcedureExecute(Oid proc_oid);

extern void sepgsqlProcedureSetup(FmgrInfo *finfo, HeapTuple protup);

extern bool sepgsqlTableLock(Oid relid);

extern bool sepgsqlTableTruncate(Relation rel);

extern void
sepgsqlSetGivenSecLabel(Relation rel, HeapTuple tuple, DefElem *defel);
extern void
sepgsqlSetGivenSecLabelList(Relation rel, HeapTuple tuple, List *secLabelList);
extern List *
sepgsqlRelationGivenSecLabelList(CreateStmt *stmt);

// COPY TO/FROM
extern void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom);
extern void
sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom);

// HeapTuple INSERT/UPDATE/DELETE
extern bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
					   bool internal, bool returning);
extern bool
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
					   bool internal, bool returning);
extern bool
sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid,
					   bool internal, bool returning);

/*
 * label.c : security label management
 */
extern bool
sepgsqlTupleDescHasSecLabel(Relation rel);

extern void
sepgsqlPostBootstrapingMode(void);

extern Oid
sepgsqlLookupSecurityId(security_context_t label);

extern security_context_t
sepgsqlLookupSecurityLabel(Oid sid);

extern Oid
sepgsqlSecurityLabelToSid(security_context_t label);

extern security_context_t
sepgsqlSidToSecurityLabel(Oid sid);

extern bool
sepgsqlCheckValidSecurityLabel(security_context_t label);

extern security_context_t
sepgsqlSecurityLabelTransIn(security_context_t label);

extern security_context_t
sepgsqlSecurityLabelTransOut(security_context_t label);

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

extern const char *sepgsqlAuditName(Oid relid, HeapTuple tuple);

extern security_class_t sepgsqlFileObjectClass(int fdesc);

extern security_class_t sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple);

extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple newtup,
								   uint32 required, bool abort);

extern void sepgsqlSetDefaultLabel(Relation rel, HeapTuple tuple);

#else	/* HAVE_SELINUX */

// analyze.c
#define sepgsqlPostQueryRewrite(a)				do {} while(0)
#define sepgsqlExecutorStart(a,b)				do {} while(0)
// avc.c
#define sepgsqlShmemSize()						(0)
#define sepgsqlStartupWorkerProcess()			(0)
// core.c
#define sepgsqlIsEnabled()						(false)
#define sepgsqlInitialize()						do {} while(0)

// hooks.c
#define sepgsqlDatabaseAccess(a)				(true)
#define sepgsqlDatabaseSetParam(a)				do {} while(0)
#define sepgsqlDatabaseGetParam(a)				do {} while(0)
#define sepgsqlDatabaseInstallModule(a)			do {} while(0)
#define sepgsqlDatabaseLoadModule(a)			do {} while(0)
#define sepgsqlProcedureExecute(a)				(true)
#define sepgsqlProcedureSetup(a)				do {} while(0)
#define sepgsqlTableLock(a)						(true)
#define sepgsqlTableTruncate(a)					(true)
#define sepgsqlSetGivenSecLabel(a,b,c)			do {} while(0)
#define sepgsqlSetGivenSecLabelList(a,b,c)		do {} while(0)
#define sepgsqlRelationGivenSecLabelList(a)		(NIL)
#define sepgsqlCopyTable(a,b,c)					do {} while(0)
#define sepgsqlCopyFile(a,b,c,d)				do {} while(0)
#define sepgsqlHeapTupleInsert(a,b,c,d)			(true)
#define sepgsqlHeapTupleUpdate(a,b,c,d,e)		(true)
#define sepgsqlHeapTupleDelete(a,b,c,d)			(true)
// label.c
#define sepgsqlTupleDescHasSecLabel(a)			(false)
#define sepgsqlPostBootstrapingMode()			do {} while(0)
#define sepgsqlSecurityLabelToSid(a)			(InvalidOid)
#define sepgsqlSidToSecurityLabel(a)			(pstrdup(""))

#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_database_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_table_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_column_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_procedure_getcon(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
