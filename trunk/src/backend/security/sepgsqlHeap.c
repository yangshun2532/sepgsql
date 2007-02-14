/*
 * src/backend/security/sepgsqlHeap.c
 *   SE-PostgreSQL heap modification hooks
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_aggregate.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_selinux.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/typcache.h"

#define OIDS_ARRAY_MAX (16)

static uint32 __tuple_perms_to_reference_perms(uint32 perms) {
	uint32 __perms = 0;
	__perms |= (perms & TUPLE__RELABELFROM ? COMMON_DATABASE__SETATTR : 0);
	__perms |= (perms & TUPLE__RELABELTO ? COMMON_DATABASE__SETATTR : 0);
	__perms |= (perms & TUPLE__SELECT ? COMMON_DATABASE__GETATTR : 0);
	__perms |= (perms & TUPLE__UPDATE ? COMMON_DATABASE__SETATTR : 0);
	__perms |= (perms & TUPLE__INSERT ? COMMON_DATABASE__CREATE : 0);
	__perms |= (perms & TUPLE__DELETE ? COMMON_DATABASE__DROP : 0);
	return __perms;
}

static uint32 __tuple_perms_to_common_perms(uint32 perms) {
	uint32 __perms = 0;
	__perms |= (perms & TUPLE__RELABELFROM ? COMMON_DATABASE__RELABELFROM : 0);
	__perms |= (perms & TUPLE__RELABELTO ? COMMON_DATABASE__RELABELTO : 0);
	__perms |= (perms & TUPLE__SELECT ? COMMON_DATABASE__GETATTR : 0);
    __perms |= (perms & TUPLE__UPDATE ? COMMON_DATABASE__SETATTR : 0);
    __perms |= (perms & TUPLE__INSERT ? COMMON_DATABASE__CREATE : 0);
    __perms |= (perms & TUPLE__DELETE ? COMMON_DATABASE__DROP : 0);
	return __perms;
}

static int __check_tuple_perms(Oid tableoid, TupleDesc tdesc, HeapTuple tuple,
							   uint32 perms, char **audit)
{
	HeapTuple exttup;
	uint16 tclass = SECCLASS_TUPLE;
	char *objname = NULL;
	Datum _objname;
	bool isnull;
	int rc;

	switch (tableoid) {
	case AggregateRelationId: {
		/* pg_aggregate */
		Datum proid = heap_getattr(tuple, Anum_pg_aggregate_aggfnoid, tdesc, &isnull);
		if (isnull)
			selerror("pg_aggregate.aggfnoid contains NULL");
		exttup = SearchSysCache(PROCOID, proid, 0, 0, 0);
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   HeapTupleGetSecurity(exttup),
							   SECCLASS_PROCEDURE,
							   __tuple_perms_to_reference_perms(perms),
							   HeapTupleGetProcedureName(exttup));
		ReleaseSysCache(exttup);
		break;
	}
	case DatabaseRelationId: {
		/* pg_database */
		tclass = SECCLASS_DATABASE;
		perms = __tuple_perms_to_common_perms(perms);

		_objname = heap_getattr(tuple, Anum_pg_database_datname, tdesc, &isnull);
		if (isnull)
			selerror("pg_database.datname contains NULL");
		objname = NameStr(*DatumGetName(_objname));
		break;
	}
	case RelationRelationId: {
		/* pg_class */
		tclass = SECCLASS_TABLE;
		perms = __tuple_perms_to_common_perms(perms);

		_objname = heap_getattr(tuple, Anum_pg_class_relname, tdesc, &isnull);
		if (isnull)
			selerror("pg_class.relname contains NULL");
		objname = NameStr(*DatumGetName(_objname));
		break;
	}
	case AttributeRelationId: {
		/* pg_attribute */
		Datum relid;

		if (IsBootstrapProcessingMode()) {
			psid tcon;
			tcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetDatabasePsid(),
										 SECCLASS_TABLE);
			sepgsql_avc_permission(sepgsqlGetClientPsid(),
								   tcon,
								   SECCLASS_TABLE,
								   __tuple_perms_to_reference_perms(perms),
								   NULL);
			tclass = SECCLASS_COLUMN;
			perms = __tuple_perms_to_common_perms(perms);
			break;
		}

		relid = heap_getattr(tuple, Anum_pg_attribute_attrelid, tdesc, &isnull);
		if (isnull)
			selerror("pg_attribute.attrelid contains NULL");
		exttup = SearchSysCache(RELOID, relid, 0, 0, 0);
		if (!HeapTupleIsValid(exttup))
			selerror("cache lookup failed for relation %u", DatumGetObjectId(relid));
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   HeapTupleGetSecurity(exttup),
							   SECCLASS_TABLE,
							   __tuple_perms_to_reference_perms(perms),
							   HeapTupleGetRelationName(exttup));
		ReleaseSysCache(exttup);
		tclass = SECCLASS_COLUMN;
		perms = __tuple_perms_to_common_perms(perms);

		_objname = heap_getattr(tuple, Anum_pg_attribute_attname, tdesc, &isnull);
		if (isnull)
			selerror("pg_attribute.attname contains NULL");
		objname = NameStr(*DatumGetName(_objname));
		break;
	}
	case ProcedureRelationId: {
		/* pg_proc */
		tclass = SECCLASS_PROCEDURE;
		perms = __tuple_perms_to_common_perms(perms);

		_objname = heap_getattr(tuple, Anum_pg_proc_proname, tdesc, &isnull);
		if (isnull)
			selerror("pg_proc.proname contains NULL");
		objname = NameStr(*DatumGetName(_objname));
		break;
	}
	case LargeObjectRelationId: {
		/* pg_largeobject */
		tclass = SECCLASS_BLOB;
		perms = __tuple_perms_to_common_perms(perms);
		break;
	}
	default:
		/* do nothing */
		break;
	}

	rc = sepgsql_avc_permission_noaudit(sepgsqlGetClientPsid(),
										HeapTupleGetSecurity(tuple),
										tclass,
										perms,
										audit,
										objname);
	return rc;
}

static int __sepgsql_tuple_perms(Oid tableoid, HeapTupleHeader rec, uint32 perms, char **audit)
{
	HeapTupleData tuple;
	TupleDesc tdesc;
	int rc;

	tdesc = lookup_rowtype_tupdesc(HeapTupleHeaderGetTypeId(rec),
								   HeapTupleHeaderGetTypMod(rec));
	tuple.t_len = HeapTupleHeaderGetDatumLength(rec);
    ItemPointerSetInvalid(&(tuple.t_self));
    tuple.t_tableOid = tableoid;
    tuple.t_data = rec;

	rc = __check_tuple_perms(tableoid, tdesc, &tuple, perms, audit);

	ReleaseTupleDesc(tdesc);

	return rc;
}

Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS)
{
	Oid tableoid = PG_GETARG_OID(0);
	HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(1);
	uint32 perms = PG_GETARG_UINT32(2);
	char *audit;
	int rc;

	rc = __sepgsql_tuple_perms(tableoid, rec, perms, &audit);
	sepgsql_audit(0, audit);

	PG_RETURN_BOOL(rc == 0);
}

Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS)
{
	Oid tableoid = PG_GETARG_OID(0);
	HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(1);
	uint32 perms = PG_GETARG_UINT32(2);
	char *audit;
	int rc;

	rc = __sepgsql_tuple_perms(tableoid, rec, perms, &audit);
	sepgsql_audit(rc, audit);

	PG_RETURN_BOOL(rc == 0);
}

static psid __getImplicitContext(Relation rel, HeapTuple tuple) {
	static psid recent_relation_relid = InvalidOid;
	static psid recent_relation_relcon = InvalidOid;
	uint16 tclass;
	psid tcon, ncon;
	HeapTuple exttup;
	Datum extoid;
	bool isnull;

	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:
		tcon = sepgsqlGetServerPsid();
		tclass = SECCLASS_DATABASE;
		break;

	case RelationRelationId:
		tcon = sepgsqlGetDatabasePsid();
		tclass = SECCLASS_TABLE;
		break;

	case AttributeRelationId: {
		tclass = SECCLASS_COLUMN;
		if (IsBootstrapProcessingMode()) {
			tcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetDatabasePsid(),
										 SECCLASS_TABLE);
			break;
		}
		extoid = heap_getattr(tuple,
							  Anum_pg_attribute_attrelid,
							  RelationGetDescr(rel),
							  &isnull);
		if (isnull)
			selerror("pg_attribute.attrelid contains NULL");

		if (recent_relation_relid == extoid) {
			tcon = recent_relation_relcon;
			break;
		}
		exttup = SearchSysCache(RELOID, extoid, 0, 0, 0);
		if (!HeapTupleIsValid(exttup))
			selerror("cache lookup failed for relation %u %s",
					 DatumGetObjectId(extoid),
					 HeapTupleGetAttributeName(tuple));
		tcon = HeapTupleGetSecurity(exttup);
		ReleaseSysCache(exttup);
		break;
	}

	case ProcedureRelationId:
		tclass = SECCLASS_PROCEDURE;
		tcon = sepgsqlGetDatabasePsid();
		break;

	case LargeObjectRelationId:
		tclass = SECCLASS_BLOB;
		tcon = sepgsqlGetDatabasePsid();
		break;

	default: {
			tclass = SECCLASS_TUPLE;
			if (IsBootstrapProcessingMode()) {
				tcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
											 sepgsqlGetDatabasePsid(),
											 SECCLASS_TABLE);
				break;
			}
			exttup = SearchSysCache(RELOID,
									ObjectIdGetDatum(RelationGetRelid(rel)),
									0, 0, 0);
			if (!HeapTupleIsValid(exttup))
				selerror("cache lookup failed for relation %u",
						 RelationGetRelid(rel));
			tcon = HeapTupleGetSecurity(exttup);
			tclass = SECCLASS_TUPLE;
			ReleaseSysCache(exttup);
		}
		break;
	}
	ncon = sepgsql_avc_createcon(sepgsqlGetClientPsid(), tcon, tclass);

	/* special case for CREATE TABLE statement */
	if (RelationGetRelid(rel) == RelationRelationId) {
		Datum x = heap_getattr(tuple,
							   ObjectIdAttributeNumber,
							   RelationGetDescr(rel),
							   &isnull);
		recent_relation_relid = DatumGetObjectId(x);
		recent_relation_relcon = ncon;
	}
	return ncon;
}

void sepgsqlExecInsert(Relation rel, HeapTuple tuple, bool has_returning)
{
	psid icon, econ;
	uint32 perms;
	char *audit;
	int rc;

	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("modifying pg_selinux is never allowed");

	icon = __getImplicitContext(rel, tuple);
	econ = HeapTupleGetSecurity(tuple);
	perms = TUPLE__INSERT;
	if (has_returning)
		perms |= TUPLE__SELECT;
	if (icon != econ)
		perms |= TUPLE__RELABELFROM;

	/* 1. implicit labeling */
	HeapTupleSetSecurity(tuple, icon);

	rc = __check_tuple_perms(RelationGetRelid(rel),
							 RelationGetDescr(rel),
							 tuple,
							 perms,
							 &audit);
	sepgsql_audit(rc, audit);

	/* 2. explicit labeling, if necessary */
	if (econ != InvalidOid && icon != econ) {
		HeapTupleSetSecurity(tuple, econ);
		rc = __check_tuple_perms(RelationGetRelid(rel),
								 RelationGetDescr(rel),
								 tuple,
								 TUPLE__RELABELTO,
								 &audit);
		sepgsql_audit(rc, audit);
	}
}

void sepgsqlExecUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup, bool has_returning)
{
	psid ocon, ncon;
	uint32 perms;
	char *audit;
	int rc;

	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("modifying pg_selinux is never allowed");

	ocon = HeapTupleGetSecurity(oldtup);
	ncon = HeapTupleGetSecurity(newtup);

	if (ocon != ncon) {
		/* relabeling happen */
		perms = TUPLE__RELABELTO;
		if (has_returning)
			perms |= TUPLE__SELECT;
		rc = __check_tuple_perms(RelationGetRelid(rel),
								 RelationGetDescr(rel),
								 newtup,
								 perms,
								 &audit);
		sepgsql_audit(rc, audit);
	}
}

void sepgsqlExecDelete(Relation rel, HeapTuple tuple)
{
	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("modifying pg_selinux is never allowed");
}

void sepgsqlHeapInsert(Relation rel, HeapTuple tuple)
{
	if (HeapTupleGetSecurity(tuple) != InvalidOid)
		return;
	HeapTupleSetSecurity(tuple, __getImplicitContext(rel, tuple));
}

void sepgsqlHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	psid newcon, oldcon;

	oldcon = HeapTupleGetSecurity(oldtup);
	newcon = HeapTupleGetSecurity(newtup);

	if (newcon == InvalidOid)
		HeapTupleSetSecurity(newtup, oldcon);
}
