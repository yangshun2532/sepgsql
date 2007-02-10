/*
 * src/backend/selinux/create_relation.c
 *    CREATE TABLE statement support
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
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
#include "sepgsql.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

static psid gentbl_psid = InvalidOid;
static psid gensysatt_psid[-FirstLowInvalidHeapAttributeNumber];

TupleDesc sepgsqlCreateRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc)
{
	Form_pg_attribute pg_attr;
	TupleDesc new_desc;
	AttrNumber attnum, psidnum = FirstLowInvalidHeapAttributeNumber;

	gentbl_psid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										sepgsqlGetDatabasePsid(),
										SECCLASS_TABLE);

	if (relkind != RELKIND_RELATION)
		goto found;
	if (IsSystemNamespace(relns) || IsToastNamespace(relns))
		goto found;

	/* add 'security_context' column, if necessary */
	for (attnum=0; attnum < tdesc->natts; attnum++) {
		pg_attr = tdesc->attrs[attnum];
		if (strcmp(NameStr(pg_attr->attname), "security_context") == 0) {
			if (pg_attr->atttypid != PSIDOID)
				selerror("type of attribute '%s' is not psid", NameStr(pg_attr->attname));
			pg_attr->attispsid = true;
			psidnum = pg_attr->attnum;
			goto found;
		}
	}

	/* add 'security_context' column */
	new_desc = CreateTemplateTupleDesc(tdesc->natts + 1, tdesc->tdhasoid);
	psidnum = new_desc->natts;
	new_desc->tdtypeid = tdesc->tdtypeid;
	new_desc->tdtypmod = tdesc->tdtypmod;
	new_desc->tdrefcount = tdesc->tdrefcount;
	for (attnum=0; attnum < psidnum - 1; attnum++)
		memcpy(new_desc->attrs[attnum], tdesc->attrs[attnum], ATTRIBUTE_TUPLE_SIZE);
	TupleDescInitEntry(new_desc, psidnum, "security_context", PSIDOID, -1, 0);
	pg_attr = new_desc->attrs[psidnum - 1];
	pg_attr->attispsid = true;
	pg_attr->attnotnull = true;
	FreeTupleDesc(tdesc);  /* release old one */
	tdesc = new_desc;

	/* prepare system attributes' context */
	for (attnum = 1; attnum < -FirstLowInvalidHeapAttributeNumber; attnum++) {
		gensysatt_psid[attnum] = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
													   gentbl_psid,
													   SECCLASS_COLUMN);
	}

found:
	for (attnum = 1 + FirstLowInvalidHeapAttributeNumber; attnum <= tdesc->natts; attnum++) {
		psid col_psid;

		if (attnum == 0)
			continue;

		col_psid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 gentbl_psid,
										 SECCLASS_COLUMN);
		if (attnum < 0) {
			/* system attributes */
			gensysatt_psid[-attnum] = col_psid;
		} else {
			/* general attributes */
			tdesc->attrs[attnum - 1]->attselcon = col_psid;
			tdesc->attrs[attnum - 1]->attispsid = (attnum == psidnum ? true : false);
		}
	}
	return tdesc;
}

TupleDesc sepgsqlCloneRelation(Oid relid, Oid relns, char relkind, TupleDesc tdesc)
{
	Form_pg_class pg_class;
	Form_pg_attribute pg_attr;
	AttrNumber attnum, natts;
	bool hasoids;
	HeapTuple tup;

	/* clone pg_class->relselcon */
	tup = SearchSysCache(RELOID,
						 ObjectIdGetDatum(relid),
						 0, 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed for relation %d", relid);
	pg_class = (Form_pg_class) GETSTRUCT(tup);
	gentbl_psid = pg_class->relselcon;
	natts = pg_class->relnatts;
	hasoids = pg_class->relhasoids;
	ReleaseSysCache(tup);

	/* clone attributes */
	for (attnum = 1 + FirstLowInvalidHeapAttributeNumber; attnum <= natts; attnum++) {
		if (attnum==0)
			continue;
		if (!hasoids && attnum==ObjectIdAttributeNumber)
			continue;

		tup = SearchSysCacheCopy(ATTNUM,
								 ObjectIdGetDatum(relid),
								 Int16GetDatum(attnum),
								 0, 0);
		if (!HeapTupleIsValid(tup))
			selerror("cache lookup failed for attribute %d of relation %u", attnum, relid);
		pg_attr = (Form_pg_attribute) GETSTRUCT(tup);
		if (attnum < 0) {
			/* system attributes */
			gensysatt_psid[-attnum] = pg_attr->attselcon;
		} else {
			/* general attributes */
			tdesc->attrs[attnum - 1]->attselcon = pg_attr->attselcon;
			tdesc->attrs[attnum - 1]->attispsid = pg_attr->attispsid;
		}
		ReleaseSysCache(tup);
	}
	return tdesc;
}

void sepgsqlPutRelationContext(Form_pg_class pg_class)
{
	Assert(gentbl_psid != InvalidOid);

	pg_class->relselcon = gentbl_psid;
	gentbl_psid = InvalidOid;
}

void sepgsqlPutSysAttributeContext(Form_pg_attribute pg_attr, AttrNumber attnum)
{
	Assert(attnum < 0 && attnum > FirstLowInvalidHeapAttributeNumber);
	Assert(gensysatt_psid[-attnum] != InvalidOid);

	pg_attr->attselcon = gensysatt_psid[-attnum];
	gensysatt_psid[-attnum] = InvalidOid;
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

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), cls->relselcon,
								SECCLASS_TABLE, perms, &audit);
	sepgsql_audit(rc, audit, NameStr(cls->relname));
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

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), attr->attselcon,
								SECCLASS_COLUMN, perms, &audit);
	sepgsql_audit(rc, audit, colname);
	ReleaseSysCache(tup);
}

void sepgsqlAlterTable(Oid relid, char relkind, TupleDesc tdesc, AlterTableCmd *cmd)
{
	if (relkind != RELKIND_RELATION)
		return;

	switch (cmd->subtype)
	{
	case AT_AddColumn:
		/* table:setattr and column:create are evaluated
		   at sepgsqlAlterTableAddColumn() */
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

void sepgsqlAlterTableAddColumn(Relation rel, Form_pg_attribute pg_attr)
{
	psid new_psid;
	char *audit;
	int rc;

	checkAlterTableRelation(RelationGetRelid(rel), TABLE__SETATTR);
	new_psid = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 RelationGetForm(rel)->relselcon,
									 SECCLASS_TABLE);

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								new_psid,
								SECCLASS_COLUMN,
								COLUMN__CREATE,
								&audit);
	sepgsql_audit(rc, audit, NameStr(pg_attr->attname));
	
	/* initialize the attribute */
	pg_attr->attispsid = false;
	pg_attr->attselcon = new_psid;
}

void sepgsqlAlterTableSetTableContext(Relation rel, Value *context)
{
	Relation pgclass;
	HeapTuple tup;
	psid old_psid, new_psid;
	char *audit;
	int rc;

	selnotice("%s: relname=%s", __FUNCTION__, RelationGetRelationName(rel));

	old_psid = RelationGetForm(rel)->relselcon;
	new_psid = DatumGetObjectId(DirectFunctionCall1(psid_in,
													CStringGetDatum(strVal(context))));

	/* 1. check table:{setattr relabelfrom} */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), old_psid,
								SECCLASS_TABLE,
								TABLE__SETATTR | TABLE__RELABELFROM,
								&audit);
	sepgsql_audit(rc, audit, RelationGetRelationName(rel));

	/* 2. check table:{relabelto} */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), new_psid,
								SECCLASS_TABLE,
								TABLE__RELABELTO,
								&audit);
	sepgsql_audit(rc, audit, RelationGetRelationName(rel));

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

void sepgsqlAlterTableSetColumnContext(Relation rel, char *colname, Value *context)
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
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								old_psid,
								SECCLASS_COLUMN,
								COLUMN__SETATTR | COLUMN__RELABELFROM,
								&audit);
	sepgsql_audit(rc, audit, colname);

	/* 2. check column:{relabelto} */
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								new_psid,
								SECCLASS_COLUMN,
								COLUMN__RELABELTO,
								&audit);
	sepgsql_audit(rc, audit, colname);

	/* 3. update pg_attribute->attselcon */
	((Form_pg_attribute) GETSTRUCT(tup))->attselcon = new_psid;
	simple_heap_update(pgattr, &tup->t_self, tup);
	CatalogUpdateIndexes(pgattr, tup);

	heap_freetuple(tup);
  	heap_close(pgattr, RowExclusiveLock);
}
