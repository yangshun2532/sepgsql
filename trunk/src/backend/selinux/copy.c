/*
 * src/backend/selinux/copy.c
 *    SE-PgSQL support for COPY TO/COPY FROM statement
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "catalog/pg_class.h"
#include "catalog/pg_attribute.h"
#include "sepgsql.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

void selinuxHookDoCopy(Relation rel, List *attnumlist, bool is_from)
{
	psid tsid, ssid = selinuxGetClientPsid();
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
	rc = libselinux_avc_permission(ssid, tsid, SECCLASS_TABLE, perm, &audit);
	selinux_audit(rc, audit, NameStr(RelationGetForm(rel)->relname));

	/* 2. checl column:select/insert for each column */
	perm = (is_from == true) ? COLUMN__INSERT : COLUMN__SELECT;
	foreach(cur, attnumlist) {
		int attnum = lfirst_int(cur) - 1;
		Form_pg_attribute attr = RelationGetDescr(rel)->attrs[attnum];

		tsid = attr->attselcon;
		rc = libselinux_avc_permission(ssid, tsid, SECCLASS_COLUMN, perm, &audit);
		selinux_audit(rc, audit, NameStr(attr->attname));
	}
}

void selinuxHookCopyFrom(Relation rel, Datum *values, char *nulls)
{
	TupleDesc tupDesc = RelationGetDescr(rel);
	uint32 perm = TUPLE__INSERT;
	psid tbl_psid, tup_psid;
	char *audit;
	int i, rc = 0;

	tbl_psid = RelationGetForm(rel)->relselcon;
	tup_psid = libselinux_avc_createcon(selinuxGetClientPsid(),
										tbl_psid,
										SECCLASS_TUPLE);
	for (i=0; i < RelationGetNumberOfAttributes(rel); i++) {
		if (!tupDesc->attrs[i]->attispsid)
			continue;
		if (nulls[i] == 'n') {
			nulls[i] = ' ';
			values[i] = ObjectIdGetDatum(tup_psid);
		} else {
			perm |= TUPLE__RELABELFROM;
			rc = libselinux_avc_permission(selinuxGetClientPsid(),
										   DatumGetObjectId(values[i]),
										   SECCLASS_TUPLE,
										   TUPLE__RELABELTO,
										   &audit);
			selinux_audit(rc, audit, NULL);
		}
		break;
	}
	rc = libselinux_avc_permission(selinuxGetClientPsid(), tup_psid,
								   SECCLASS_TUPLE, perm, &audit);
	selinux_audit(rc, audit, NULL);
}

bool selinuxHookCopyTo(Relation rel, HeapTuple tuple)
{
	TupleDesc tupDesc = RelationGetDescr(rel);
	Datum tup_psid;
	bool isnull;
	int i, rc;

	for (i=0; i < RelationGetNumberOfAttributes(rel); i++) {
		if (!tupDesc->attrs[i]->attispsid)
			continue;

		tup_psid = heap_getattr(tuple, i, tupDesc, &isnull);
		rc = libselinux_avc_permission(selinuxGetClientPsid(),
									   DatumGetObjectId(tup_psid),
									   SECCLASS_TUPLE,
									   TUPLE__SELECT,
									   NULL);
		if (rc != 0)
			return false;
		break;
	}
	return true;
}
