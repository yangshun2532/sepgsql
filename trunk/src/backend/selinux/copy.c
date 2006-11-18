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
#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
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
	psid isid, esid;
	char *audit;
	int i, rc;

	isid = selinuxComputeNewTupleContext(RelationGetRelid(rel),
										 RelationGetForm(rel)->relselcon,
										 NULL);

	for (i=0; i < RelationGetNumberOfAttributes(rel); i++) {
		Form_pg_attribute attr = RelationGetDescr(rel)->attrs[i];
		if (!selinuxAttributeIsPsid(attr))
			continue;
		if (nulls[i] == 'n')
			selerror("NULL was set at 'security_context'");

		esid = DatumGetObjectId(values[i]);
		if (isid == esid) {
			rc = libselinux_avc_permission(selinuxGetClientPsid(),
										   DatumGetObjectId(isid),
										   SECCLASS_TUPLE,
										   TUPLE__INSERT,
										   &audit);
			selinux_audit(rc, audit, NULL);
		} else {
			rc = libselinux_avc_permission(selinuxGetClientPsid(),
										   DatumGetObjectId(isid),
										   SECCLASS_TUPLE,
										   TUPLE__INSERT | TUPLE__RELABELFROM,
										   &audit);
			selinux_audit(rc, audit, NULL);

			rc = libselinux_avc_permission(selinuxGetClientPsid(),
										   DatumGetObjectId(esid),
										   SECCLASS_TUPLE,
										   TUPLE__RELABELTO,
										   &audit);
			selinux_audit(rc, audit, NULL);
		}
	}
}

Node *selinuxHookCopyFromNewContext(Relation rel)
{
	psid new_sid;

	new_sid = libselinux_avc_createcon(selinuxGetClientPsid(),
									   RelationGetForm(rel)->relselcon,
									   SECCLASS_TUPLE);
	return (Node *)makeConst(PSIDOID, sizeof(psid),
							 ObjectIdGetDatum(new_sid),
							 false, false);
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
