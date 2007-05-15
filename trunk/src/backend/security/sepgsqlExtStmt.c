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

/* make context = 'xxx' node */
DefElem *sepgsqlGramSecurityLabel(char *defname, char *context) {
	DefElem *n = NULL;
	if (!strcmp(defname, "context"))
		n = makeDefElem(pstrdup(defname), (Node *) makeString(context));
	return n;
}

bool sepgsqlIsDefElemSecurityLabel(DefElem *def) {
	Assert(IsA(def, DefElem));
	if (!strcmp(def->defname, "context"))
		return true;
	return false;
}

/* ALTER TABLE tblname [ALTER colname] CONTEXT = 'xxx' */
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
	char *context;
	DefElem *def = (DefElem *) cmd->def;

	Assert(IsA(def, DefElem) && IsA(def->arg, String));
	Assert(!strcmp("context", def->defname));

	context = strVal(def->arg);

	return (!cmd->name
			? alterTableSetTableContext(rel, context)
			: alterTableSetColumnContext(rel, cmd->name, context));
}

/* CREATE FUNCTION fnname ... CONTEXT = 'xxx' */
void sepgsqlCreateFunction(Relation rel, HeapTuple tuple, char *context) {
	Datum newcon = DirectFunctionCall1(security_label_in,
									   CStringGetDatum(context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(newcon));
}

/* ALTER FUNCTION fnname CONTEXT = 'xxx' */
void sepgsqlAlterFunction(Relation rel, HeapTuple tuple, char *context) {
	sepgsqlCreateFunction(rel, tuple, context);
}

/* CREATE DATABASE dbname CONTEXT = 'xxx' */
void sepgsqlCreateDatabase(Relation rel, HeapTuple tuple, char *context) {
	Datum newcon = DirectFunctionCall1(security_label_in,
									   CStringGetDatum(context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(newcon));
}

/* ALTER DATABASE dbname CONTEXT = 'xxx' */
void sepgsqlAlterDatabase(Relation rel, HeapTuple tuple, char *context) {
	sepgsqlCreateDatabase(rel, tuple, context);
}
