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

/* CREATE TABLE tblname ( ... ) CONTEXT = 'xxx' statement */
void sepgsqlCreateRelation(Relation rel, HeapTuple tuple, char *context) {
	Datum newcon = DirectFunctionCall1(security_label_in,
									   CStringGetDatum(context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(newcon));
}

void sepgsqlCreateAttribute(Relation rel, HeapTuple tuple, char *context) {
	Datum newcon = DirectFunctionCall1(security_label_in,
									   CStringGetDatum(context));
	HeapTupleSetSecurity(tuple, DatumGetObjectId(newcon));
}

/* ALTER TABLE tblname [ALTER colname] CONTEXT = 'xxx' statement */
void sepgsqlAlterRelation(Relation rel, HeapTuple tuple, char *context) {
	sepgsqlCreateRelation(rel, tuple, context);
}

void sepgsqlAlterAttribute(Relation rel, HeapTuple tuple, char *context) {
	sepgsqlCreateAttribute(rel, tuple, context);
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
