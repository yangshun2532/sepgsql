/*
 * src/include/utils/sepgsql.h
 *    Headers of SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H


/*
 * SE-PostgreSQL working mode
 */
typedef enum
{
	SEPGSQL_MODE_DEFAULT,
	SEPGSQL_MODE_ENFORCING,
	SEPGSQL_MODE_PERMISSIVE,
	SEPGSQL_MODE_DISABLED,
} SepgsqlModeType;

extern int sepostgresql_mode;

#ifdef HAVE_SELINUX

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

/* workaround for older av_permissions.h */
#ifndef	DB_PROCEDURE__INSTALL
#define	DB_PROCEDURE__INSTALL		0x00000100UL
#endif

extern bool
sepgsqlTupleDescHasSecLabel(Relation rel);



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


#endif	/* HAVE_SELINUX */

extern Datum sepgsql_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_server_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_database_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_table_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_column_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_procedure_getcon(PG_FUNCTION_ARGS);

#endif	/* SEPGSQL_H */
