/*
 * src/backend/selinux/selinux.c
 *    SE-PgSQL bootstrap hook functions.
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "executor/executor.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "sepgsql.h"
#include "utils/syscache.h"

static psid getImplicitContext(HeapTuple tuple, Relation rel, uint16 *p_tclass, uint32 *p_perms)
{
	psid tsid;
	uint16 tclass;
	uint32 perms;

	switch (RelationGetRelid(rel)) {
	case AttributeRelationId: {
		HeapTuple reltup;
		Oid relid;
		bool isNull;

		relid = DatumGetObjectId(heap_getattr(tuple, TableOidAttributeNumber,
											  RelationGetDescr(rel), &isNull));
		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(relid),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			selerror("cache lookup failed for relid=%u", relid);
		tsid = ((Form_pg_class) GETSTRUCT(reltup))->relselcon;
		ReleaseSysCache(reltup);

		tclass = SECCLASS_COLUMN;
		perms = COLUMN__CREATE;
		break;
	}
	case RelationRelationId:
		tsid = sepgsqlGetDatabasePsid();
		tclass = SECCLASS_TABLE;
		perms = TABLE__CREATE;
		break;
    case DatabaseRelationId:
        tsid = sepgsqlGetServerPsid();
        tclass = SECCLASS_DATABASE;
		perms = DATABASE__CREATE;
        break;
    case ProcedureRelationId:
        tsid = sepgsqlGetDatabasePsid();
        tclass = SECCLASS_PROCEDURE;
		perms = PROCEDURE__CREATE;
        break;
    case LargeObjectRelationId:
		tsid = sepgsqlGetDatabasePsid();
		tclass = SECCLASS_BLOB;
		perms = BLOB__CREATE;
		break;
    default:
        tsid = RelationGetForm(rel)->relselcon;;
        tclass = SECCLASS_TUPLE;
		perms = TUPLE__INSERT;
        break;
	}
	if (p_tclass)
		*p_tclass = tclass;
	if (p_perms)
		*p_perms = perms;
	return sepgsql_avc_createcon(sepgsqlGetClientPsid(), tsid, tclass);
}

HeapTuple sepgsqlExecInsert(EState *estate, ResultRelInfo *resRelInfo, HeapTuple tuple)
{
	Relation rel = resRelInfo->ri_RelationDesc;
	TupleDesc tdesc = RelationGetDescr(rel);
	HeapTuple newtuple = tuple;
	MemoryContext oldContext;
	AttrNumber attno;
	uint16 tclass;
	uint32 perms;
	char *audit;
	int rc;

	oldContext = GetPerTupleMemoryContext(estate);
	oldContext = MemoryContextSwitchTo(oldContext);

	for (attno=0; attno < RelationGetNumberOfAttributes(rel); attno++) {
		Form_pg_attribute attr = tdesc->attrs[attno];

		if (sepgsqlAttributeIsPsid(attr)) {
			bool isnull;
			psid icon, econ;

			icon = getImplicitContext(tuple, rel, &tclass, &perms);
			econ = DatumGetObjectId(heap_getattr(tuple, attr->attnum, tdesc, &isnull));
			if (isnull) {
				/* implicit labeling behavior */
				Datum *values;
				bool *isNull, *doRepl;
				HeapTuple oldtuple;

				rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
											icon, tclass, perms, &audit);
				sepgsql_audit(rc, audit, NULL);

				values = palloc0(sizeof(Datum) * tdesc->natts);
				isNull = palloc0(sizeof(bool) * tdesc->natts);
				doRepl = palloc0(sizeof(bool) * tdesc->natts);

				values[attr->attnum - 1] = ObjectIdGetDatum(icon);
				isNull[attr->attnum - 1] = false;
				doRepl[attr->attnum - 1] = true;

				oldtuple = newtuple;
				newtuple = heap_modify_tuple(newtuple, tdesc, values, isNull, doRepl);
				if (oldtuple != tuple)
					heap_freetuple(oldtuple);
			} else {
				/* check explicit labeling */
				if (icon != econ)
					perms |= ((tclass == SECCLASS_TUPLE)
							  ? TUPLE__RELABELFROM
							  : COMMON_DATABASE__RELABELFROM);
				rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
											icon, tclass, perms, &audit);
				sepgsql_audit(rc, audit, NULL);
				if (icon != econ) {
					perms = ((tclass == SECCLASS_TUPLE)
							 ? TUPLE__RELABELTO
							 : COMMON_DATABASE__RELABELTO);
					rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
												econ, tclass, perms, &audit);
					sepgsql_audit(rc, audit, NULL);
				}
			}
		}
	}
	MemoryContextSwitchTo(oldContext);

	return newtuple;
}

HeapTuple sepgsqlExecUpdate(EState *estate, ResultRelInfo *resRelInfo, HeapTuple tuple)
{
	return tuple;
}

