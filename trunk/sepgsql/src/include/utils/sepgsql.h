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
 * core.c : core facilities
 */
extern security_context_t sepgsqlGetServerLabel(void);

extern security_context_t sepgsqlGetClientLabel(void);

extern security_context_t sepgsqlSwitchClientLabel(char *new_label);

extern security_context_t sepgsqlGetUnlabeledLabel(void);

extern security_context_t sepgsqlGetDatabaseLabel(void);

extern Oid	sepgsqlGetDatabaseSid(void);

extern bool	sepgsqlIsEnabled(void);



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

extern void
sepgsqlClientHasPerms(Oid tsid, security_class_t tclass,
					  access_vector_t perms, const char *audit_name);

extern bool
sepgsqlClientHasPermsNoAbort(Oid tsid, security_class_t tclass,
							 access_vector_t perms, const char *audit_name);
extern Oid
sepgsqlClientCreateSid(Oid tsid, security_class_t tclass);

extern security_context_t
sepgsqlClientCreateLabel(Oid tsid, security_class_t tclass);

extern bool
sepgsqlComputePerms(security_context_t scontext,
					security_context_t tcontext,
					security_class_t tclass,
					access_vector_t perms,
					const char *audit_name);

extern security_context_t
sepgsqlComputeCreateContext(security_context_t scontext,
							security_context_t tcontext,
							security_class_t tclass);

/*
 * hooks.c : security hooks
 */
extern bool sepgsqlDatabaseAccess(Oid db_oid);

extern void sepgsqlDatabaseSetParam(const char *name);

extern void sepgsqlDatabaseGetParam(const char *name);

extern bool sepgsqlProcedureExecute(Oid proc_oid);

extern bool sepgsqlTableLock(Oid relid);

extern bool sepgsqlTableTruncate(Relation rel);

extern void sepgsqlProcessUtility(Node *parsetree, ParamListInfo params, bool isTopLevel);

extern void sepgsqlLoadSharedModule(const char *filename);

extern void sepgsqlProcedureSetup(FmgrInfo *finfo, HeapTuple protup);

/* SECURITY_LABEL = '...' statement */
extern void
sepgsqlSetGivenSecLabel(Relation rel, HeapTuple tuple, DefElem *defel);
extern void
sepgsqlSetGivenSecLabelList(Relation rel, HeapTuple tuple, List *secLabelList);
extern List *
sepgsqlRelationGivenSecLabelList(CreateStmt *stmt);

/* COPY TO/FROM */
extern void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom);
extern void
sepgsqlCopyFile(Relation rel, int fdesc, const char *filename, bool isFrom);

/* INSERT/UPDATE/DELETE */
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
extern bool sepgsqlTupleDescHasSecLabel(Relation rel);

extern void sepgsqlPostBootstrapingMode(void);

extern Oid sepgsqlLookupSecurityId(char *label);

extern char *sepgsqlLookupSecurityLabel(Oid sid);

extern Oid sepgsqlSecurityLabelToSid(char *label);

extern char *sepgsqlSidToSecurityLabel(Oid sid);

extern bool sepgsqlCheckValidSecurityLabel(char *context);

extern char *sepgsqlSecurityLabelTransIn(const char *context);

extern char *sepgsqlSecurityLabelTransOut(const char *context);

/*
 * perms.c : permission checks by SE-PostgreSQL
 */
extern const char *sepgsqlAuditName(Oid relid, HeapTuple tuple);

extern security_class_t sepgsqlFileObjectClass(int fdesc);

extern security_class_t sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple);

extern bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple newtup,
								   uint32 required, bool abort);

extern void sepgsqlSetDefaultLabel(Relation rel, HeapTuple tuple);

extern void sepgsqlCheckModuleInstallPerms(const char *filename);

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







#else	/* HAVE_SELINUX */

/*
 * core.c : core facilities
 */
#define sepgsqlIsEnabled()					(false)

/*
 * avc.c : userspace access vector cache
 */
#define sepgsqlShmemSize()					(0)
#define sepgsqlAvcInit()					do {} while(0)
#define sepgsqlStartupWorkerProcess()		do {} while(0)

/*
 * hooks.c : security hooks
 */
#define sepgsqlDatabaseAccess(a)			do {} while(0)
#define sepgsqlProcedureExecute(a)			do {} while(0)

#define sepgsqlHeapTupleInsert(a,b,c,d)		(true)
#define sepgsqlHeapTupleUpdate(a,b,c,d,e)	(true)
#define sepgsqlHeapTupleDelete(a,b,c,d)		(true)

#define sepgsqlCopyTable(a,b,c)				do {} while(0)
#define sepgsqlCopyFile(a,b,c,d)			do {} while(0)


/*
 * label.c : security label stuff
 */
#define sepgsqlTupleDescHasSecLabel(a)		(false)
#define sepgsqlPostBootstrapingMode()		do {} while(0)
#define sepgsqlSecurityLabelToSid(a)		(InvalidOid)
#define sepgsqlSidToSecurityLabel(a)		(NULL)




#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_database_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_table_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_column_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_procedure_getcon(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
