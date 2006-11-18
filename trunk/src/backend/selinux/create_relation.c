/*
 * src/backend/selinux/create_relation.c
 *    CREATE TABLE statement support
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/htup.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "nodes/makefuncs.h"
#include "sepgsql.h"
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
