/*
 * src/backend/security/sepgsqlHooks.c
 *   SE-PostgreSQL hook functions for several strategic point.
 *
 *  Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "security/sepgsql.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * ALTER TABLE statement related
 */
static psid __alterTableGetColmnContext(Oid relid, char *colname)
{
	HeapTuple atttup;
	AttrNumber attno;
	psid attcon;

	attno = get_attnum(relid, colname);
    if (attno == InvalidAttrNumber)
		selerror("column %s of relation %u does not exist", colname, relid);
	atttup = SearchSysCache(ATTNUM,
							ObjectIdGetDatum(relid),
							Int16GetDatum(attno),
							0, 0);
	if (!HeapTupleIsValid(atttup))
		selerror("cache lookup failed for column %s of relation %u",
				 colname, relid);
	attcon = HeapTupleGetSecurity(atttup);
	ReleaseSysCache(atttup);

	return attcon;
}

void sepgsqlAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd)
{
	HeapTuple reltup;
	psid newcon;

	if (relkind != RELKIND_RELATION)
		return;

	reltup = SearchSysCache(RELOID,
							ObjectIdGetDatum(relid),
							0, 0, 0);
	if (!HeapTupleIsValid(reltup))
		selerror("cache lookup failed for relation %u", relid);

	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(reltup),
						   SECCLASS_TABLE,
						   TABLE__SETATTR,
						   HeapTupleGetRelationName(reltup));

	switch (cmd->subtype)
	{
	case AT_AddColumn:
		newcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									   HeapTupleGetSecurity(reltup),
									   SECCLASS_COLUMN);
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   newcon,
							   SECCLASS_COLUMN,
							   COLUMN__CREATE,
							   ((ColumnDef *) cmd->def)->colname);
		break;

	case AT_ColumnDefault:
	case AT_DropNotNull:
	case AT_SetStatistics:
	case AT_SetStorage:
	case AT_AlterColumnType:
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   __alterTableGetColmnContext(relid, cmd->name),
							   SECCLASS_COLUMN,
							   COLUMN__SETATTR,
							   cmd->name);
		break;

	case AT_DropColumn:
	case AT_DropColumnRecurse:
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   __alterTableGetColmnContext(relid, cmd->name),
							   SECCLASS_COLUMN,
							   COLUMN__DROP,
							   cmd->name);
		break;
		
	case AT_AddIndex:
	case AT_ReAddIndex:
	case AT_AddConstraint:
	case AT_ProcessedConstraint:
	case AT_DropOids:
		/* FIXME: what to be done? */
		break;

	case AT_SetTableSpace:
	case AT_SetRelOptions:
	case AT_ResetRelOptions:
	case AT_EnableTrig:
	case AT_DisableTrig:
	case AT_EnableTrigAll:
	case AT_DisableTrigAll:
	case AT_EnableTrigUser:
	case AT_DisableTrigUser:
	case AT_AddInherit:
	case AT_DropInherit:
		break;
	default:
		selnotice("cmd->subtype=%d, was not evaluated at SE-PgSQL", cmd->subtype);
		break;
	}
}

void sepgsqlAlterTableSetTableContext(Relation rel, Value *context)
{
	Relation pgclass;
	HeapTuple tuple;
	psid newcon, oldcon;
	Datum datum;

	pgclass = heap_open(RelationRelationId, RowExclusiveLock);

	/* lookup old security context */
	tuple = SearchSysCacheCopy(RELOID,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));
	oldcon = HeapTupleGetSecurity(tuple);

	/* lookup new security context */
	datum = DirectFunctionCall1(psid_in, CStringGetDatum(strVal(context)));
	newcon = DatumGetObjectId(datum);

	/* 1. check table:{setattr relabelfrom} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   oldcon,
						   SECCLASS_TABLE,
						   TABLE__SETATTR | TABLE__RELABELFROM,
						   HeapTupleGetRelationName(tuple));

	/* 2. check table:{relabelto} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   newcon,
						   SECCLASS_TABLE,
						   TABLE__RELABELTO,
						   HeapTupleGetRelationName(tuple));

	/* 3. update pg_class */
	HeapTupleSetSecurity(tuple, newcon);
	simple_heap_update(pgclass, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pgclass, tuple);

	heap_freetuple(tuple);
	heap_close(pgclass, RowExclusiveLock);
}

void sepgsqlAlterTableSetColumnContext(Relation rel, char *colname, Value *context)
{
	Relation pgattribute;
	HeapTuple tuple;
	psid newcon, oldcon;
	Datum datum;
	char objname[2*NAMEDATALEN + 1];

	snprintf(objname, sizeof(objname), "%s/%s", RelationGetRelationName(rel), colname);

	pgattribute = heap_open(AttributeRelationId, RowExclusiveLock);

	/* lookup old security context */
	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colname);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed, column %s of relation %s",
				 colname, RelationGetRelationName(rel));
	oldcon = HeapTupleGetSecurity(tuple);

	/* lookup new security context */
	datum = DirectFunctionCall1(psid_in, CStringGetDatum(strVal(context)));
	newcon = DatumGetObjectId(datum);

	/* 1. check column:{setattr relabelfrom} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   oldcon,
						   SECCLASS_COLUMN,
						   COLUMN__SETATTR | COLUMN__RELABELFROM,
						   objname);

	/* 2. check column:{relabelto} */
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   newcon,
						   SECCLASS_COLUMN,
						   COLUMN__RELABELTO,
						   objname);

	/* 3. update pg_attribute->attselcon */
	HeapTupleSetSecurity(tuple, newcon);
	simple_heap_update(pgattribute, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pgattribute, tuple);

	heap_freetuple(tuple);
  	heap_close(pgattribute, RowExclusiveLock);
}

/*
 * Trusted Procedure support
 */
static Datum sepgsqlExprStateEvalFunc(ExprState *expression,
									  ExprContext *econtext,
									  bool *isNull,
									  ExprDoneCond *isDone)
{
	Datum retval;
	psid saved_clientcon;

	/* save security context */
	saved_clientcon = sepgsqlGetClientPsid();
	sepgsqlSetClientPsid(expression->execContext);
	PG_TRY();
	{
		retval = expression->origEvalFunc(expression, econtext, isNull, isDone);
	}
	PG_CATCH();
	{
		sepgsqlSetClientPsid(saved_clientcon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	/* restore context */
	sepgsqlSetClientPsid(saved_clientcon);

	return retval;
}

void sepgsqlExecInitExpr(ExprState *state, PlanState *parent)
{
	switch (nodeTag(state->expr)) {
	case T_FuncExpr:
		{
			FuncExpr *func = (FuncExpr *) state->expr;
			HeapTuple tuple;
			psid execon;

			tuple = SearchSysCache(PROCOID, ObjectIdGetDatum(func->funcid), 0, 0, 0);
			if (!HeapTupleIsValid(tuple))
				selerror("RELOID cache lookup failed (pg_proc.oid=%u)", func->funcid);
			execon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										   HeapTupleGetSecurity(tuple),
										   SECCLASS_PROCESS);
			if (sepgsqlGetClientPsid() != execon) {
				/* do domain transition */
				state->execContext = execon;
				state->origEvalFunc = state->evalfunc;
				state->evalfunc = sepgsqlExprStateEvalFunc;
			}
			ReleaseSysCache(tuple);
		}
		break;
	default:
		/* do nothing */
		break;
	}
}

/*
 * CREATE/DROP/ALTER FUNCTION statement
 */
void sepgsqlCreateProcedure(HeapTuple tuple)
{
	psid ncon;

	ncon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								 sepgsqlGetDatabasePsid(),
								 SECCLASS_PROCEDURE);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_PROCEDURE,
						   PROCEDURE__CREATE,
						   HeapTupleGetProcedureName(tuple));
}

void sepgsqlAlterProcedure(HeapTuple tuple, char *proselcon)
{
	psid ocon, ncon = InvalidOid;
	uint32 perms;

	ocon = HeapTupleGetSecurity(tuple);
	perms = DATABASE__SETATTR;
	if (proselcon) {
		Datum _ncon = DirectFunctionCall1(psid_in, CStringGetDatum(proselcon));
		ncon = DatumGetObjectId(_ncon);
		if (ocon != ncon)
			perms |= PROCEDURE__RELABELFROM;
	}

	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   ocon,
						   SECCLASS_PROCEDURE,
						   perms,
						   HeapTupleGetDatabaseName(tuple));
	if (ocon != ncon) {
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   ncon,
							   SECCLASS_PROCEDURE,
							   PROCEDURE__RELABELTO,
							   HeapTupleGetProcedureName(tuple));
		HeapTupleSetSecurity(tuple, ncon);
	}
}

void sepgsqlDropProcedure(HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_PROCEDURE,
						   PROCEDURE__DROP,
						   HeapTupleGetProcedureName(tuple));
}

/*
 * COPY TO/COPY FROM statement support
 */
void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from)
{
	HeapTuple tuple;
	uint32 perms;
	ListCell *l;

	/* on 'COPY FROM SELECT ...' cases, any checkings are done in select.c */
	if (rel == NULL)
		return;

	/* 1. check table:select/insert permission */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(RelationGetRelid(rel)),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));

	perms = (is_from ? TABLE__INSERT : TABLE__SELECT);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_TABLE,
						   perms,
						   HeapTupleGetRelationName(tuple));
	ReleaseSysCache(tuple);

	/* 2. check column:select/insert for each column */
	perms = (is_from ? COLUMN__INSERT : COLUMN__SELECT);
	foreach(l, attnumlist) {
		char objname[2 * NAMEDATALEN + 1];
		AttrNumber attno = lfirst_int(l);

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   Int16GetDatum(attno),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			selerror("cache lookup failed for attribute %d, relation %u",
					 attno, RelationGetRelid(rel));

		snprintf(objname, sizeof(objname), "%s.%s",
				 RelationGetRelationName(rel),
				 HeapTupleGetAttributeName(tuple));

		perms = (is_from ? COLUMN__INSERT : COLUMN__SELECT);
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   HeapTupleGetSecurity(tuple),
							   SECCLASS_COLUMN,
							   perms,
							   objname);
		ReleaseSysCache(tuple);
	}
}

bool sepgsqlCopyTo(Relation rel, HeapTuple tuple)
{
	Datum rc;

	rc = DirectFunctionCall3(sepgsql_tuple_perms,
							 ObjectIdGetDatum(RelationGetRelid(rel)),
							 PointerGetDatum(tuple->t_data),
							 Int32GetDatum(TUPLE__SELECT));
	return BoolGetDatum(rc);
}

/*
 * DATABASE statement related
 */
void sepgsqlCreateDatabase(HeapTuple tuple)
{
	psid ncon;
	ncon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								 sepgsqlGetServerPsid(),
								 SECCLASS_DATABASE);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__CREATE,
						   HeapTupleGetDatabaseName(tuple));
}

void sepgsqlAlterDatabase(HeapTuple tuple, char *dselcon)
{
	psid ocon, ncon = InvalidOid;
	uint32 perms;

	ocon = HeapTupleGetSecurity(tuple);
	perms = DATABASE__SETATTR;
	if (dselcon) {
		Datum _ncon = DirectFunctionCall1(psid_in, CStringGetDatum(dselcon));
		ncon = DatumGetObjectId(_ncon);
		if (ocon != ncon)
			perms |= DATABASE__RELABELFROM;
	}

	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   ocon,
						   SECCLASS_DATABASE,
						   perms,
						   HeapTupleGetDatabaseName(tuple));
	if (ocon != ncon) {
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   ncon,
							   SECCLASS_DATABASE,
							   DATABASE__RELABELTO,
							   HeapTupleGetDatabaseName(tuple));
		HeapTupleSetSecurity(tuple, ncon);
	}
}

void sepgsqlDropDatabase(HeapTuple tuple)
{
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   HeapTupleGetSecurity(tuple),
						   SECCLASS_DATABASE,
						   DATABASE__DROP,
						   HeapTupleGetDatabaseName(tuple));
}
