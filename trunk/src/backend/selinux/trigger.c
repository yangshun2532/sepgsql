/*
 * src/backend/selinux/trigger.c
 *    SE-PgSQL hard coded trigger functions.
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/heapam.h"
#include "executor/executor.h"
#include "catalog/catalog.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "sepgsql.h"
#include "utils/syscache.h"

static inline Oid __heap_getoid(HeapTuple tuple, AttrNumber attno, TupleDesc tdesc, bool *isnull)
{
	return DatumGetObjectId(heap_getattr(tuple, attno, tdesc, isnull));
}

static psid __checkRelationSetattr(Oid relid)
{
	Form_pg_class pgclass;
	HeapTuple tup;
	psid relcon;
	char *audit;
	int rc;

	tup = SearchSysCache(RELOID,
						 ObjectIdGetDatum(relid),
						 0, 0, 0);
	if (!HeapTupleIsValid(tup))
		selerror("cache lookup failed for relid=%u", relid);

	pgclass = (Form_pg_class) GETSTRUCT(tup);
	relcon = pgclass->relselcon;

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), relcon,
								SECCLASS_TABLE, TABLE__SETATTR,
								&audit);
	sepgsql_audit(rc, audit, NameStr(pgclass->relname));

	ReleaseSysCache(tup);

	return relcon;
}

HeapTuple sepgsqlExecInsert(HeapTuple newtup, MemoryContext mcontext,
							Relation rel, ProjectionInfo *retProj)
{
	TupleDesc tdesc = RelationGetDescr(rel);
	Oid relid;
	psid icon, econ;
	AttrNumber attno;
	uint16 tclass;
	uint32 perms;
	bool isnull;
	char *audit;
	int rc;

	/*
	 * The following switch() {...} statement set the five variable.
	 * tclass : target class to be applied
	 * attno  : attribute number of security context
	 * icon   : Implicitly computed context
	 * econ   : Explicitly provided context
	 * isnull : whether 'econ' is NULL, or not
	 */   
	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:
		tclass = SECCLASS_DATABASE;
		attno = Anum_pg_database_datselcon;
		icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 sepgsqlGetServerPsid(),
									 tclass);
		econ = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
		break;

	case RelationRelationId:
		tclass = SECCLASS_TABLE;
		attno = Anum_pg_class_relselcon;
		icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 sepgsqlGetDatabasePsid(),
									 tclass);
		econ = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
		break;

	case AttributeRelationId:
		tclass = SECCLASS_COLUMN;
		attno = Anum_pg_attribute_attselcon;
		relid = DatumGetObjectId(heap_getattr(newtup, Anum_pg_attribute_attrelid,
											  tdesc, &isnull));
		if (isnull)
			selerror("pg_attribute.attrelid is NULL");
		icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 __checkRelationSetattr(relid),
									 tclass);
		econ = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
		break;

	case ProcedureRelationId:
		tclass = SECCLASS_PROCEDURE;
		attno = Anum_pg_proc_proselcon;
		icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 sepgsqlGetDatabasePsid(),
									 tclass);
		econ = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
		break;

	case LargeObjectRelationId:
		tclass = SECCLASS_BLOB;
		attno = Anum_pg_largeobject_selcon;
		icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
                                     sepgsqlGetDatabasePsid(),
                                     tclass);
		econ = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
		break;

	default:
		tclass = SECCLASS_TUPLE;
		icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
									 RelationGetForm(rel)->relselcon,
									 tclass);
		econ = InvalidOid; /* for compiler kindness */
		for (attno = 1; attno <= RelationGetNumberOfAttributes(rel); attno++) {
			Form_pg_attribute attr = tdesc->attrs[attno - 1];
			if (sepgsqlAttributeIsPsid(attr)) {
				econ = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
				break;
			}
		}
		break;
	}

	if (attno < 1 || attno > RelationGetNumberOfAttributes(rel))
		return newtup;  /* do nothing */

	perms = ((tclass == SECCLASS_TUPLE)
			 ? TUPLE__INSERT : COMMON_DATABASE__CREATE);
	if (isnull) {
		MemoryContext oldContext;
		Datum *values;
		bool *nulls, *repls;

		/* no explicit labeling */
		if (retProj)
			perms |= ((tclass == SECCLASS_TUPLE)
					  ? TUPLE__SELECT : COMMON_DATABASE__GETATTR);
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									icon, tclass, perms, &audit);
		sepgsql_audit(rc, audit, NULL);

		oldContext = MemoryContextSwitchTo(mcontext);
		values = palloc0(sizeof(Datum) * tdesc->natts);
		nulls  = palloc0(sizeof(bool)  * tdesc->natts);
		repls  = palloc0(sizeof(bool)  * tdesc->natts);

		values[attno - 1] = ObjectIdGetDatum(icon);
		nulls[attno - 1] = false;
		repls[attno - 1] = true;

		newtup = heap_modify_tuple(newtup, tdesc, values, nulls, repls);

		pfree(values);
		pfree(nulls);
		pfree(repls);

		MemoryContextSwitchTo(oldContext);
	} else {
		/* explicit labeling */
		if (icon != econ) {
			perms |= ((tclass == SECCLASS_TUPLE)
					  ? TUPLE__RELABELFROM : COMMON_DATABASE__RELABELFROM);
		} else if (retProj) {
			perms |= ((tclass == SECCLASS_TUPLE)
					  ? TUPLE__SELECT : COMMON_DATABASE__GETATTR);
		}
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), icon,
									tclass, perms, &audit);
		sepgsql_audit(rc, audit, NULL);

		if (icon != econ) {
			perms = ((tclass == SECCLASS_TUPLE)
					 ? TUPLE__RELABELTO : COMMON_DATABASE__RELABELTO);
			if (retProj)
				perms |= ((tclass == SECCLASS_TUPLE)
						  ? TUPLE__SELECT : COMMON_DATABASE__GETATTR);
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), econ,
										tclass, perms, &audit);
			sepgsql_audit(rc, audit, NULL);
		}
	}
	return newtup;
}

HeapTuple sepgsqlExecUpdate(HeapTuple newtup, HeapTuple oldtup,
							Relation rel, ProjectionInfo *retProj)
{
	TupleDesc tdesc = RelationGetDescr(rel);
	AttrNumber attno, relid_attno = 0;
	uint16 tclass;

	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:
		tclass = SECCLASS_DATABASE;
		attno = Anum_pg_database_datselcon;
		break;
	case RelationRelationId:
		tclass = SECCLASS_TABLE;
		attno = Anum_pg_class_relselcon;
		break;
	case AttributeRelationId:
		relid_attno = Anum_pg_attribute_attrelid;
		tclass = SECCLASS_COLUMN;
		attno = Anum_pg_attribute_attselcon;
		break;
	break;
		tclass = SECCLASS_COLUMN;
		attno = Anum_pg_attribute_attselcon;
		break;
	case ProcedureRelationId:
		tclass = SECCLASS_PROCEDURE;
		attno = Anum_pg_proc_proselcon;
		break;
	case LargeObjectRelationId:
		tclass = SECCLASS_BLOB;
		attno = Anum_pg_largeobject_selcon;
		break;
	default:
		tclass = SECCLASS_TUPLE;
		for (attno = 1; attno <= RelationGetNumberOfAttributes(rel); attno++) {
			if (sepgsqlAttributeIsPsid(tdesc->attrs[attno - 1]))
				break;
		}
		break;
	}

	/* check table:{setattr}, if necessary */
	if (relid_attno > 0 && relid_attno <= RelationGetNumberOfAttributes(rel)) {
		Oid old_relid, new_relid;
		bool isnull;

		old_relid = DatumGetObjectId(heap_getattr(oldtup, relid_attno, tdesc, &isnull));
		if (isnull)
			selerror("Old Relation OID was NULL");
		__checkRelationSetattr(old_relid);

		new_relid = DatumGetObjectId(heap_getattr(newtup, relid_attno, tdesc, &isnull));
		if (isnull)
			selerror("New Relation OID was NULL");
		if (old_relid != new_relid)
			__checkRelationSetattr(new_relid);
	}

	if (attno > 0 && attno <= RelationGetNumberOfAttributes(rel)) {
		Form_pg_attribute attr = tdesc->attrs[attno - 1];
		psid oldcon, newcon;
		uint32 perms;
		bool isnull;
		char *audit;
		int rc;

		perms = ((tclass == SECCLASS_TUPLE)
				 ? TUPLE__UPDATE : COMMON_DATABASE__SETATTR);

		oldcon = DatumGetObjectId(heap_getattr(oldtup, attno, tdesc, &isnull));
		if (isnull)
			selerror("%s.%s contained NULL", RelationGetRelationName(rel), NameStr(attr->attname));

		newcon = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
		if (isnull)
			selerror("%s.%s contained NULL", RelationGetRelationName(rel), NameStr(attr->attname));

		if (oldcon == newcon) {
			/* no relabeling */
			if (retProj)
				perms |= ((tclass == SECCLASS_TUPLE)
						  ? TUPLE__SELECT : COMMON_DATABASE__GETATTR);
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), oldcon,
										tclass, perms, &audit);
			sepgsql_audit(rc, audit, NameStr(attr->attname));
		} else {
			/* security context may be changed */
			perms |= ((tclass == SECCLASS_TUPLE)
                      ? TUPLE__RELABELFROM : COMMON_DATABASE__RELABELFROM);
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), oldcon,
                                        tclass, perms, &audit);
            sepgsql_audit(rc, audit, NameStr(attr->attname));

			perms |= ((tclass == SECCLASS_TUPLE)
                      ? TUPLE__RELABELTO : COMMON_DATABASE__RELABELTO);
			if (retProj)
				perms |= ((tclass == SECCLASS_TUPLE)
						  ? TUPLE__SELECT : COMMON_DATABASE__GETATTR);
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(), newcon,
										tclass, perms, &audit);
		}
	}
	return newtup;
}

bool sepgsqlExecDelete(HeapTuple oldtup, Relation rel, ProjectionInfo *retProj)
{
	/* do nothing now */
	return true;
}
