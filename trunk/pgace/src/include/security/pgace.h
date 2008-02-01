/*
 * include/security/pgace.h
 *   headers for PostgreSQL Access Control Extensions (PGACE)
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#ifndef PGACE_H
#define PGACE_H

#include "access/htup.h"
#include "commands/trigger.h"
#include "executor/execdesc.h"
#include "nodes/parsenodes.h"
#include "utils/builtins.h"
#include "utils/rel.h"

/*
 * SECURITY_SYSATTR_NAME is the name of system column name
 * for security attribute, defined in pg_config.h
 * If it is not defined, security attribute support is disabled
 *
 * see, src/include/pg_config.h
 */

/******************************************************************
 * Initialize / Finalize related hooks
 ******************************************************************/
extern Size pgaceShmemSize(void);
extern void pgaceInitialize(bool is_bootstrap);
extern bool pgaceInitializePostmaster(void);
extern void pgaceFinalizePostmaster(void);

/******************************************************************
 * SQL proxy hooks
 ******************************************************************/
extern List *pgaceProxyQuery(List *queryList);
extern void  pgacePortalStart(Portal portal);
extern void  pgaceExecutorStart(QueryDesc *queryDesc, int eflags);

/******************************************************************
 * HeapTuple modification hooks
 ******************************************************************/
extern bool pgaceHeapTupleInsert(Relation rel, HeapTuple tuple,
								 bool is_internal, bool with_returning);
extern bool pgaceHeapTupleUpdate(Relation rel, ItemPointer otid, HeapTuple newtup,
								 bool is_internal, bool with_returning);
extern bool pgaceHeapTupleDelete(Relation rel, ItemPointer otid,
								 bool is_internal, bool with_returning);

/******************************************************************
 * Extended SQL statement hooks
 ******************************************************************/
extern DefElem *pgaceGramSecurityItem(char *defname, char *value);
extern bool pgaceIsGramSecurityItem(DefElem *defel);
extern void pgaceGramCreateRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterRelation(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterAttribute(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterDatabase(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramCreateFunction(Relation rel, HeapTuple tuple, DefElem *defel);
extern void pgaceGramAlterFunction(Relation rel, HeapTuple tuple, DefElem *defel);

/******************************************************************
 * DATABASE related hooks
 ******************************************************************/
extern void pgaceSetDatabaseParam(const char *name, char *argstring);
extern void pgaceGetDatabaseParam(const char *name);

/******************************************************************
 * FUNCTION related hooks
 ******************************************************************/
extern void pgaceCallFunction(FmgrInfo *finfo);
extern bool pgaceCallFunctionTrigger(FmgrInfo *finfo, TriggerData *tgdata);
extern void pgaceCallFunctionFastPath(FmgrInfo *finfo);
extern Datum pgacePreparePlanCheck(Relation rel);
extern void pgaceRestorePlanCheck(Relation rel, Datum pgace_saved);

/******************************************************************
 * TABLE related hooks
 ******************************************************************/
extern void pgaceLockTable(Oid relid);

/******************************************************************
 * COPY TO/COPY FROM statement hooks
 ******************************************************************/
extern void pgaceCopyTable(Relation rel, List *attNumList, bool isFrom);
extern bool pgaceCopyToTuple(Relation rel, List *attNumList, HeapTuple tuple);

/******************************************************************
 * Loadable shared library module hooks
 ******************************************************************/
extern void pgaceLoadSharedModule(const char *filename);

/******************************************************************
 * Binary Large Object (BLOB) hooks
 ******************************************************************/
extern void pgaceLargeObjectGetSecurity(HeapTuple tuple);
extern void pgaceLargeObjectSetSecurity(HeapTuple tuple, Oid lo_security);
extern void pgaceLargeObjectCreate(Relation rel, HeapTuple tuple);
extern void pgaceLargeObjectDrop(Relation rel, HeapTuple tuple);
extern void pgaceLargeObjectOpen(Relation rel, HeapTuple tuple, bool read_only);
extern void pgaceLargeObjectRead(Relation rel, HeapTuple tuple, bool is_first);
extern void pgaceLargeObjectWrite(Relation rel, HeapTuple newtup, HeapTuple oldtup, bool is_first);
extern void pgaceLargeObjectTruncate(Relation rel, Oid loid);
extern void pgaceLargeObjectImport(int fd);
extern void pgaceLargeObjectExport(int fd, Oid loid);

/******************************************************************
 * Security Label hooks
 ******************************************************************/
extern char *pgaceSecurityLabelIn(char *seclabel);
extern char *pgaceSecurityLabelOut(char *seclabel);
extern char *pgaceSecurityLabelCheckValid(char *seclabel);
extern char *pgaceSecurityLabelOfLabel(char *new_label);

/******************************************************************
 * Extended node type hooks
 ******************************************************************/
extern Node *pgaceCopyObject(Node *orig);
extern bool  pgaceOutObject(StringInfo str, Node *node);
extern void *pgaceReadObject(char *token);

/******************************************************************
 * PGACE common facilities (not a hooks)
 ******************************************************************/
/* Security attribute system column support */
extern bool pgaceIsSecuritySystemColumn(int attrno);
extern void pgaceFetchSecurityAttribute(JunkFilter *junkfilter, TupleTableSlot *slot, Oid *tts_security);
extern void pgaceTransformSelectStmt(List *targetList);
extern void pgaceTransformInsertStmt(List **p_icolumns, List **p_attrnos, List *targetList);

/* Extended SQL statements related */
extern List *pgaceRelationAttrList(CreateStmt *stmt);
extern void  pgaceCreateRelationCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list);
extern void  pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list);
extern void  pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd);

/* SQL functions */
extern Datum security_label_in(PG_FUNCTION_ARGS);
extern Datum security_label_out(PG_FUNCTION_ARGS);
extern Datum security_label_raw_in(PG_FUNCTION_ARGS);
extern Datum security_label_raw_out(PG_FUNCTION_ARGS);
extern Datum text_to_security_label(PG_FUNCTION_ARGS);
extern Datum security_label_to_text(PG_FUNCTION_ARGS);
extern Datum lo_get_security(PG_FUNCTION_ARGS);
extern Datum lo_set_security(PG_FUNCTION_ARGS);

#endif // PGACE_H
