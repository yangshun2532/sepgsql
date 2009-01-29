/*
 * src/include/utils/sepgsql.h
 *    Headers of SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

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
extern const security_context_t sepgsqlGetServerContext(void);

extern const security_context_t sepgsqlGetClientContext(void);

extern const security_context_t sepgsqlGetUnlabeledContext(void);

extern const security_context_t sepgsqlGetDatabaseContext(void);

extern Oid sepgsqlGetDatabaseSid(void);

extern bool sepgsqlIsEnabled(void);

/*
 * label.c : security label management
 */
extern bool sepgsqlTupleDescHasSecLabel(Relation rel);

extern void sepgsqlPostBootstrapingMode(void);

extern Oid sepgsqlLookupSecurityId(const char *label);

extern char *sepgsqlLookupSecurityLabel(Oid sid);

extern Oid sepgsqlSecurityLabelToSid(const char *label);

extern char *sepgsqlSidToSecurityLabel(Oid sid);

/*
 * hooks.c : security hooks
 */
extern void sepgsqlDatabaseAccess(Oid db_oid);

extern void sepgsqlProcedureExecute(Oid proc_oid);

extern void
sepgsqlSetGivenSecLabel(Relation rel, HeapTuple tuple, DefElem *defel);
extern void
sepgsqlSetGivenSecLabelList(Relation rel, HeapTuple tuple, List *secLabelList);


extern void
sepgsqlCopyTable(Relation rel, List *attNumList, bool isFrom);
extern void
sepgsqlCopyFile(Relation rel, const char *filename, bool isFrom);



extern bool
sepgsqlHeapTupleInsert(Relation rel, HeapTuple tuple,
					   bool is_internal, bool with_returning);
extern bool
sepgsqlHeapTupleUpdate(Relation rel, ItemPointer otid,
					   HeapTuple newtup, bool is_internal,
					   bool with_returning);
extern bool
sepgsqlHeapTupleDelete(Relation rel, ItemPointer otid,
					   bool is_internal, bool with_returning);



#else	/* HAVE_SELINUX */

/*
 * core.c : core facilities
 */
#define sepgsqlIsEnabled()					(false)

/*
 * hooks.c : security hooks
 */
#define sepgsqlDatabaseAccess(a)			do {} while(0)
#define sepgsqlProcedureExecute(a)			do {} while(0)

#define sepgsqlHeapTupleInsert(a,b,c,d)		(true)
#define sepgsqlHeapTupleUpdate(a,b,c,d,e)	(true)
#define sepgsqlHeapTupleDelete(a,b,c,d)		(true)

#define sepgsqlCopyTable(a,b,c)				do {} while(0)
#define sepgsqlCopyFile(a,b,c)				do {} while(0)




#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_database_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_table_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_column_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_procedure_getcon(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
