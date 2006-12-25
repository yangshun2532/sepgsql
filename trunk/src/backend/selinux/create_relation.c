/*
 * src/backend/selinux/create_relation.c
 *    CREATE TABLE statement support
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "nodes/makefuncs.h"
#include "sepgsql.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

Query *selinuxProxyCreateTable(Query *query)
{
	CreateStmt *stmt = (CreateStmt *)query->utilityStmt;
	ColumnDef *column;
	Oid nsid;

	/* no additional column on system catalog */
	nsid = RangeVarGetCreationNamespace(stmt->relation);
	if (nsid == PG_CATALOG_NAMESPACE)
		return query;

	/* add security context column */
	column = makeNode(ColumnDef);
	column->colname = pstrdup("security_context");
	column->typename = makeTypeName("psid");
	column->constraints = NIL;
	column->is_local = true;
	column->is_not_null = true;
	column->is_selcon = true;
	
	stmt->tableElts = lappend(stmt->tableElts, column);
	
	return query;
}

/* we have to full up those values before heap_create_with_catalog */
static psid next_table_psid = InvalidOid;
static psid next_sysatt_psid[-FirstLowInvalidHeapAttributeNumber];

void selinuxHookPutRelselcon(Form_pg_class pg_class)
{
	Assert(next_table_psid != InvalidOid);

	pg_class->relselcon = next_table_psid;
	next_table_psid = InvalidOid;
}

void selinuxHookPutSysAttselcon(Form_pg_attribute pg_attr, int attnum)
{
	Assert(attnum < 0 && attnum > FirstLowInvalidHeapAttributeNumber);
	Assert(next_sysatt_psid[-attnum] != InvalidOid);

	pg_attr->attselcon = next_sysatt_psid[-attnum];
	next_sysatt_psid[-attnum] = InvalidOid;
}

void selinuxHookCreateRelation(TupleDesc tupDesc, char relkind, List *schema)
{
	psid tblcon, colcon;
	int i = 0;

	tblcon = libselinux_avc_createcon(selinuxGetClientPsid(),
									  selinuxGetDatabasePsid(),
									  SECCLASS_TABLE);
	colcon = libselinux_avc_createcon(selinuxGetClientPsid(),
									  tblcon,
									  SECCLASS_COLUMN);

	if (schema != NULL) {
		ListCell *item;

		foreach(item, schema) {
			ColumnDef *column = lfirst(item);

			tupDesc->attrs[i]->attispsid = column->is_selcon;
			tupDesc->attrs[i]->attselcon = colcon;
			i++;
		}
	} else {
		for (i=0; i < tupDesc->natts; i++) {
			tupDesc->attrs[i]->attispsid = false;
			tupDesc->attrs[i]->attselcon = colcon;
		}
	}

	next_table_psid = tblcon;
	for (i=0; i < lengthof(next_sysatt_psid); i++)
		next_sysatt_psid[i] = colcon;
}

void selinuxHookCloneRelation(TupleDesc tupDesc, Relation relOrig)
{
	HeapTuple tuple;
	int i;

	next_table_psid = relOrig->rd_rel->relselcon;

	for (i=-1; i > FirstLowInvalidHeapAttributeNumber; i--) {
		Form_pg_attribute att_tup;

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(relOrig->rd_id),
							   Int16GetDatum(i), 0, 0);
		if (!HeapTupleIsValid(tuple))
			continue;

		att_tup = (Form_pg_attribute) GETSTRUCT(tuple);
		next_sysatt_psid[-i] = att_tup->attselcon;
		ReleaseSysCache(tuple);
	}
}

static void checkAlterTableRelation(Oid relid, uint32 perms)
{
	Form_pg_class cls;
	HeapTuple tup;
	char *audit;
	int rc;

	tup = SearchSysCache(RELOID,
						 ObjectIdGetDatum(relid),
						 0, 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed for relation %u", relid);
	cls = (Form_pg_class) GETSTRUCT(tup);

	rc = libselinux_avc_permission(selinuxGetClientPsid(), cls->relselcon,
								   SECCLASS_TABLE, perms, &audit);
	selinux_audit(rc, audit, NameStr(cls->relname));
	ReleaseSysCache(tup);
}

static void checkAlterTableColumn(Oid relid, char *colname, uint32 perms)
{
	Form_pg_attribute attr;
	AttrNumber attnum;
	HeapTuple tup;
	char *audit;
	int rc;

	attnum = get_attnum(relid, colname);
	if (attnum == InvalidAttrNumber)
		selerror("column '%s' of relation '%u' does not exist",
				 colname, relid);

	tup = SearchSysCache(ATTNUM,
						 ObjectIdGetDatum(relid),
						 Int16GetDatum(attnum),
						 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed for attribute %d of relation %u",
				 attnum, relid);
	attr = (Form_pg_attribute) GETSTRUCT(tup);

	rc = libselinux_avc_permission(selinuxGetClientPsid(), attr->attselcon,
								   SECCLASS_COLUMN, perms, &audit);
	selinux_audit(rc, audit, colname);
	ReleaseSysCache(tup);
}

void selinuxHookAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd)
{
	if (relkind != RELKIND_RELATION)
		return;

	switch (cmd->subtype)
	{
	case AT_AddColumn:
		/* table:setattr and column:create are evaluated
		   at selinuxHookAlterTableAddColumn() */
		break;

	case AT_ColumnDefault:
	case AT_DropNotNull:
	case AT_SetStatistics:
	case AT_SetStorage:
	case AT_AlterColumnType:
		checkAlterTableColumn(relid, cmd->name, COLUMN__SETATTR);
		break;

	case AT_DropColumn:
	case AT_DropColumnRecurse:
		checkAlterTableRelation(relid, TABLE__SETATTR);
		checkAlterTableColumn(relid, cmd->name, COLUMN__DROP);
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
		checkAlterTableRelation(relid, TABLE__SETATTR);
		break;
	default:
		selnotice("cmd->subtype=%d, was not evaluated at SE-PgSQL", cmd->subtype);
		break;
	}
}

void selinuxHookAlterTableAddColumn(Relation rel, Form_pg_attribute pg_attr)
{
	psid new_psid;
	char *audit;
	int rc;

	checkAlterTableRelation(RelationGetRelid(rel), TABLE__SETATTR);
	new_psid = libselinux_avc_createcon(selinuxGetClientPsid(),
										RelationGetForm(rel)->relselcon,
										SECCLASS_TABLE);

	rc = libselinux_avc_permission(selinuxGetClientPsid(),
								   new_psid,
								   SECCLASS_COLUMN,
								   COLUMN__CREATE,
								   &audit);
	selinux_audit(rc, audit, NameStr(pg_attr->attname));
	
	/* initialize the attribute */
	pg_attr->attispsid = false;
	pg_attr->attselcon = new_psid;
}

void selinuxHookAlterTableSetTableContext(Relation rel, Value *context)
{
	Relation pgclass;
	HeapTuple tup;
	psid old_psid, new_psid;
	Datum tmp;
	char *audit;
	int rc;

	selnotice("%s: relname=%s", __FUNCTION__, RelationGetRelationName(rel));

	old_psid = RelationGetForm(rel)->relselcon;
	new_psid = DatumGetObjectId(DirectFunctionCall1(psid_in,
													CStringGetDatum(strVal(context))));

	/* 1. check table:{setattr relabelfrom} */
	rc = libselinux_avc_permission(selinuxGetClientPsid(), old_psid,
								   SECCLASS_TABLE,
								   TABLE__SETATTR | TABLE__RELABELFROM,
								   &audit);
	selinux_audit(rc, audit, RelationGetRelationName(rel));

	/* 2. check table:{relabelto} */
	rc = libselinux_avc_permission(selinuxGetClientPsid(), new_psid,
								   SECCLASS_TABLE,
								   TABLE__RELABELTO,
								   &audit);
	selinux_audit(rc, audit, RelationGetRelationName(rel));

	/* 3. update pg_class */
	pgclass = heap_open(RelationRelationId, RowExclusiveLock);
	tup = SearchSysCacheCopy(RELOID, ObjectIdGetDatum(RelationGetRelid(rel)), 0, 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed for relation %u", RelationGetRelid(rel));

	((Form_pg_class) GETSTRUCT(tup))->relselcon = new_psid;
	simple_heap_update(pgclass, &tup->t_self, tup);
	CatalogUpdateIndexes(pgclass, tup);
	
	heap_freetuple(tup);
	heap_close(pgclass, RowExclusiveLock);
}

void selinuxHookAlterTableSetColumnContext(Relation rel, char *colname, Value *context)
{
	HeapTuple tup;
	AttrNumber attnum;
	Relation pgattr;
	psid old_psid, new_psid;
	char *audit;
	int rc;

	pgattr = heap_open(AttributeRelationId, RowExclusiveLock);
	tup = SearchSysCacheCopyAttName(RelationGetRelid(rel), colname);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed, column '%s' of relation '%s' dose not exist",
				 colname, RelationGetRelationName(rel));

	attnum = ((Form_pg_attribute) GETSTRUCT(tup))->attnum;
	if (attnum <= 0)
		selerror("cannot alter system column '%s'", colname);

	old_psid = ((Form_pg_attribute) GETSTRUCT(tup))->attselcon;
	new_psid = DatumGetObjectId(DirectFunctionCall1(psid_in,
													CStringGetDatum(strVal(context))));

	/* 1. check column:{setattr relabelfrom} */
	rc = libselinux_avc_permission(selinuxGetClientPsid(),
								   old_psid,
								   SECCLASS_COLUMN,
								   COLUMN__SETATTR | COLUMN__RELABELFROM,
								   &audit);
	selinux_audit(rc, audit, colname);

	/* 2. check column:{relabelto} */
	rc = libselinux_avc_permission(selinuxGetClientPsid(),
								   new_psid,
								   SECCLASS_COLUMN,
								   COLUMN__RELABELTO,
								   &audit);
	selinux_audit(rc, audit, colname);

	/* 3. update pg_attribute->attselcon */
	((Form_pg_attribute) GETSTRUCT(tup))->attselcon = new_psid;
	simple_heap_update(pgattr, &tup->t_self, tup);
	CatalogUpdateIndexes(pgattr, tup);

	heap_freetuple(tup);
  	heap_close(pgattr, RowExclusiveLock);
}
