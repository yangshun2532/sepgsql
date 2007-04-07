/*
 * src/backend/security/sepgsqlExtStmt.c
 *   SE-PostgreSQL extended statement support.
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "nodes/makefuncs.h"
#include "nodes/parsenodes.h"
#include "security/pgace.h"
#include "utils/syscache.h"

/* ALTER TABLE tblname [ALTER colname] CONTEXT = 'xxx' */
#define AT_SetTableContext			(AT_DropInherit + 1)

AlterTableCmd *sepgsqlGramAlterTable(char *colName, char *key, char *value) {
	AlterTableCmd *cmd = NULL;
	if (!strcmp(key, "context")) {
		cmd = makeNode(AlterTableCmd);
		cmd->subtype = AT_SetTableContext;
		cmd->name = colName;
		cmd->def = (Node *) makeString(value);
	}
	return cmd;
}

bool sepgsqlAlterTablePrepare(Relation rel, AlterTableCmd *cmd) {
	return (cmd->subtype == AT_SetTableContext ? true : false);
}

static bool alterTableSetTableContext(Relation rel, char *context)
{
	Relation pgclass;
	HeapTuple tuple;
	Datum newcon;

	pgclass = heap_open(RelationRelationId, RowExclusiveLock);
	tuple = SearchSysCacheCopy(RELOID,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));

	/* lookup new security context */
	newcon = DirectFunctionCall1(security_label_in,
								 CStringGetDatum(context));
	/* set new security context */
	HeapTupleSetSecurity(tuple, ObjectIdGetDatum(newcon));

	/* all checks are done in simple_heap_update */
	simple_heap_update(pgclass, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pgclass, tuple);

	heap_freetuple(tuple);
	heap_close(pgclass, RowExclusiveLock);

	return true;
}

static bool alterTableSetColumnContext(Relation rel, char *colname, char *context)
{
	Relation pgattr;
	HeapTuple tuple;
	Datum newcon;

	pgattr = heap_open(AttributeRelationId, RowExclusiveLock);

	/* obtain old tuple */
	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colname);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed, column %s of relation %s",
				 colname, RelationGetRelationName(rel));

	/* lookup new security context */
	newcon = DirectFunctionCall1(security_label_in,
								 CStringGetDatum(context));
	/* set new security context */
	HeapTupleSetSecurity(tuple, ObjectIdGetDatum(newcon));

	/* all checks are done in simple_heap_update */
	simple_heap_update(pgattr, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pgattr, tuple);

	heap_freetuple(tuple);
  	heap_close(pgattr, RowExclusiveLock);

	return true;
}

bool sepgsqlAlterTable(Relation rel, AlterTableCmd *cmd) {
	if (cmd->subtype != AT_SetTableContext)
		return false;
	return (!cmd->name
			? alterTableSetTableContext(rel, strVal(cmd->def))
			: alterTableSetColumnContext(rel, cmd->name, strVal(cmd->def)));
}

/* ALTER FUNCTION fnname CONTEXT = 'xxx' */
DefElem *sepgsqlGramAlterFunction(char *defname, char *value) {
	DefElem *n = NULL;
	if (!strcmp(defname, "context"))
		n = makeDefElem("context", (Node *) makeString(value));
	return n;
}

void pgsqlAlterFunction(Relation rel, HeapTuple tuple, char *context) {
	Datum ncon;

	Assert(RelationGetRelid(rel) == ProcedureRelationId);
	ncon = DirectFunctionCall1(security_label_in,
							   CStringGetDatum(context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(ncon));
}

/* ALTER DATABASE dbname CONTEXT = 'xxx' */
DefElem *sepgsqlGramAlterDatabase(char *defname, char *context) {
	DefElem *n = NULL;
	if (!strcmp(defname, "context"))
		n = makeDefElem("context", (Node *) makeString(context));
	return n;
}

void pgsqlAlterDatabase(Relation rel, HeapTuple tuple, char *context) {
	Datum ncon;

	Assert(RelationGetRelid(rel) == DatabaseRelationId);
	ncon = DirectFunctionCall1(security_label_in,
							   CStringGetDatum(context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(ncon));
}
