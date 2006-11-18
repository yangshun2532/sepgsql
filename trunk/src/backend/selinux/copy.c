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

	new_sid = selinuxComputeNewTupleContext(RelationGetRelid(rel),
											RelationGetForm(rel)->relselcon,
											NULL);
	return (Node *)makeConst(PSIDOID, sizeof(psid),
							 ObjectIdGetDatum(new_sid),
							 false, false);
}

bool selinuxHookCopyTo(Relation rel, HeapTuple tuple)
{
	TupleDesc tupDesc = RelationGetDescr(rel);
	Oid relid = RelationGetRelid(rel);
	uint16 tclass;
	uint32 perm;
	Datum tup_psid;
	bool isnull;
	char relkind;
	int i, rc;

	for (i=0; i < RelationGetNumberOfAttributes(rel); i++) {
		if (!selinuxAttributeIsPsid(tupDesc->attrs[i]))
			continue;

		tup_psid = heap_getattr(tuple, i+1, tupDesc, &isnull);
		if (isnull)
			selerror("'security_context' is NULL at '%s'",
					 RelationGetRelationName(rel));

		switch (relid) {
		case AttributeRelationId:
			tclass = SECCLASS_COLUMN;
			perm = COLUMN__GETATTR;
			break;
		case RelationRelationId:
			relkind = heap_getattr(tuple, Anum_pg_class_relkind, tupDesc, &isnull);
			if (isnull)
				selerror("'relkind' is NULL at '%s'",
						 RelationGetRelationName(rel));
			if (relkind == RELKIND_RELATION) {
				tclass = SECCLASS_TABLE;
				perm = TABLE__GETATTR;
			} else {
				tclass = SECCLASS_TUPLE;
				perm = TUPLE__SELECT;
			}
			break;
		case DatabaseRelationId:
			tclass = SECCLASS_DATABASE;
			perm = DATABASE__GETATTR;
			break;
		case ProcedureRelationId:
			tclass = SECCLASS_PROCEDURE;
			perm = PROCEDURE__GETATTR;
			break;
		case LargeObjectRelationId:
			tclass = SECCLASS_BLOB;
			perm = BLOB__GETATTR;
			break;
		default:
			tclass = SECCLASS_TUPLE;
			perm = TUPLE__SELECT;
		}
		rc = libselinux_avc_permission(selinuxGetClientPsid(),
									   DatumGetObjectId(tup_psid),
									   tclass, perm, NULL);
		if (rc != 0)
			return false;
		break;
	}
	return true;
}
