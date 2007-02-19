/*
 * src/backend/security/sepgsqlRelation.c
 *   SE-PostgreSQL hooks related to any relation objects.
 *
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/indexing.h"
#include "security/sepgsql.h"
#include "utils/lsyscache.h"

/*
 * CREATE TABLE statement related
 */
void sepgsqlCreateRelation(Relation rel, HeapTuple tuple)
{
	psid ncon;

	Assert(RelationGetRelid(rel) == RelationRelationId);
	ncon = sepgsqlComputeImplicitContext(rel, tuple);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__INSERT);
}

void sepgsqlCreateAttribute(Relation rel, HeapTuple tuple)
{
	psid ncon;

	Assert(RelationGetRelid(rel) == AttributeRelationId);
	ncon = sepgsqlComputeImplicitContext(rel, tuple);
	HeapTupleSetSecurity(tuple, ncon);
	sepgsqlCheckTuplePerms(rel, tuple, TUPLE__INSERT);
}

/*
 * DROP TABLE statement related
 */
void sepgsqlDropRelation(Relation rel, HeapTuple tuple)
{

}






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
	ReleaseSysCache(reltup);
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

