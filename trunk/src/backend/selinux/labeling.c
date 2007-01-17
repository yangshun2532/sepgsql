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

HeapTuple sepgsqlExecInsert(HeapTuple tuple, Relation rel, MemoryContext mcontext)
{
	TupleDesc tdesc = RelationGetDescr(rel);
	HeapTuple newtuple = tuple;
	MemoryContext oldContext;
	AttrNumber attno;
	uint16 tclass;
	uint32 perms;
	char *audit;
	int rc;

	oldContext = MemoryContextSwitchTo(mcontext);

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

HeapTuple sepgsqlExecUpdate(HeapTuple newtup, HeapTuple oldtup, Relation rel, MemoryContext mcontext)
{
	TupleDesc tdesc = RelationGetDescr(rel);
	AttrNumber attno;
	uint16 tclass;
	uint32 from_perm = COMMON_DATABASE__RELABELFROM;
	uint32 to_perm = COMMON_DATABASE__RELABELTO;
	char *audit;
	int rc;

	switch (RelationGetRelid(rel)) {
	case AttributeRelationId:   tclass = SECCLASS_COLUMN;    break;
	case RelationRelationId:    tclass = SECCLASS_TABLE;     break;
	case DatabaseRelationId:    tclass = DATABASE__CREATE;   break;
	case ProcedureRelationId:   tclass = SECCLASS_PROCEDURE; break;
	case LargeObjectRelationId: tclass = SECCLASS_BLOB;      break;
	default:
		tclass = SECCLASS_TUPLE;
		from_perm = TUPLE__RELABELFROM;
		to_perm = TUPLE__RELABELTO;
		break;
	}

	for (attno=0; attno < RelationGetNumberOfAttributes(rel); attno++) {
		Form_pg_attribute attr = tdesc->attrs[attno];

		if (sepgsqlAttributeIsPsid(attr)) {
			psid oldcon, newcon;
			bool isnull;

			oldcon = DatumGetObjectId(heap_getattr(oldtup, attr->attnum, tdesc, &isnull));
			if (isnull)
				selerror("%s.%s cannot contain NULL",
						 RelationGetRelationName(rel),
						 NameStr(attr->attname));
			newcon = DatumGetObjectId(heap_getattr(newtup, attr->attnum, tdesc, &isnull));
			if (isnull)
				selerror("%s.%s cannot contain NULL",
						 RelationGetRelationName(rel),
						 NameStr(attr->attname));
			if (oldcon != newcon) {
				rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
											oldcon, tclass, from_perm, &audit);
				sepgsql_audit(rc, audit, NameStr(attr->attname));
				rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
											newcon, tclass, to_perm, &audit);
				sepgsql_audit(rc, audit, NameStr(attr->attname));
			}
		}
	}
	return newtup;
}
