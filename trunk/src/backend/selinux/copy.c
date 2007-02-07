/*
 * src/backend/selinux/copy.c
 *    SE-PgSQL support for COPY TO/COPY FROM statement
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "sepgsql.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

void sepgsqlDoCopy(Relation rel, List *attnumlist, bool is_from)
{
	psid tsid, ssid = sepgsqlGetClientPsid();
	uint32 perm;
	char *audit;
	int rc;
	ListCell *cur;

	/* on 'COPY FROM SELECT ...' cases, any checkings are done in select.c */
	if (rel == NULL)
		return;

	/* 1. check table:select/insert permission */
	perm = (is_from == true) ? TABLE__INSERT : TABLE__SELECT;
	tsid = RelationGetForm(rel)->relselcon;
	rc = sepgsql_avc_permission(ssid, tsid, SECCLASS_TABLE, perm, &audit);
	sepgsql_audit(rc, audit, NameStr(RelationGetForm(rel)->relname));

	/* 2. checl column:select/insert for each column */
	perm = (is_from == true) ? COLUMN__INSERT : COLUMN__SELECT;
	foreach(cur, attnumlist) {
		int attnum = lfirst_int(cur) - 1;
		Form_pg_attribute attr = RelationGetDescr(rel)->attrs[attnum];

		tsid = attr->attselcon;
		rc = sepgsql_avc_permission(ssid, tsid, SECCLASS_COLUMN, perm, &audit);
		sepgsql_audit(rc, audit, NameStr(attr->attname));
	}
}

bool sepgsqlCopyTo(Relation rel, HeapTuple tuple)
{
	return sepgsql_tuple_perm_copyto(rel, tuple, TUPLE__SELECT);
}
