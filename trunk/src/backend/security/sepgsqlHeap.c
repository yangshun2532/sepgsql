/*
 * src/backend/security/sepgsqlHeap.c
 *   SE-PostgreSQL heap modification hooks
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_aggregate.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_auth_members.h"
#include "catalog/pg_authid.h"
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

/*
 * special cases for operations on system catalogs
 */
static void __check_pg_aggregate(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
								 uint16 *p_tclass, uint32 *p_perms, char **p_objname)
{
	HeapTuple exttup;
	Datum proid;
	bool isnull;

	proid = heap_getattr(tuple, Anum_pg_aggregate_aggfnoid, tdesc, &isnull);
	if (isnull)
		selerror("pg_aggregate.aggfnoid contains NULL");

	exttup = SearchSysCache(PROCOID, proid, 0, 0, 0);
	if (!HeapTupleIsValid(exttup))
		selerror("cache lookup failed for procedure %u", DatumGetObjectId(proid));
	sepgsql_avc_permission(sepgsqlGetClientPsid(),
						   sepgsqlGetDatabasePsid(),
						   SECCLASS_PROCEDURE,
						   __tuple_perms_to_reference_perms(perms),
						   HeapTupleGetProcedureName(exttup));
	ReleaseSysCache(exttup);
}

static void __check_pg_attribute(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
								 uint16 *p_tclass, uint32 *p_perms, char **p_objname)
{
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);

	*p_objname = NameStr(attr->attname);

	/* special case in bootstraping mode */
	if (IsBootstrapProcessingMode()
		&& (attr->attrelid == TypeRelationId ||
			attr->attrelid == ProcedureRelationId ||
			attr->attrelid == AttributeRelationId ||
			attr->attrelid == ProcedureRelationId)) {
		psid tcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										  sepgsqlGetDatabasePsid(),
										  SECCLASS_TABLE);
		sepgsql_avc_permission(sepgsqlGetClientPsid(),
							   tcon,
							   SECCLASS_TABLE,
							   __tuple_perms_to_reference_perms(perms),
							   "hogehoge");
		*p_tclass = SECCLASS_COLUMN;
		*p_perms = __tuple_perms_to_common_perms(perms);
	} else {
		HeapTuple exttup;
		Form_pg_class pgclass;

		exttup = SearchSysCache(RELOID, ObjectIdGetDatum(attr->attrelid), 0, 0, 0);
		if (!HeapTupleIsValid(exttup))
			selerror("cache lookup failed for relation %u", attr->attrelid);
		pgclass = (Form_pg_class) GETSTRUCT(exttup);

		if (pgclass->relkind == RELKIND_RELATION) {
			sepgsql_avc_permission(sepgsqlGetClientPsid(),
								   HeapTupleGetSecurity(exttup),
								   SECCLASS_TABLE,
								   __tuple_perms_to_reference_perms(perms),
								   NameStr(pgclass->relname));
		} else {
			uint32 __perms = 0;

			if (pgclass->relkind == RELKIND_VIEW) {
				__perms |= (perms & TUPLE__INSERT ? DATABASE__CREATE_VIEW : 0);
				__perms |= (perms & TUPLE__UPDATE ? DATABASE__ALTER_VIEW : 0);
				__perms |= (perms & TUPLE__DELETE ? DATABASE__DROP_VIEW : 0);
			} else {
				__perms |= (perms & TUPLE__INSERT ? DATABASE__CREATE_MISC : 0);
				__perms |= (perms & TUPLE__UPDATE ? DATABASE__ALTER_MISC : 0);
				__perms |= (perms & TUPLE__DELETE ? DATABASE__DROP_VIEW : 0);
			}
			if (__perms) {
				sepgsql_avc_permission(sepgsqlGetClientPsid(),
									   sepgsqlGetDatabasePsid(),
									   SECCLASS_DATABASE,
									   __perms,
									   NameStr(pgclass->relname));
			}
		}
		ReleaseSysCache(exttup);

		*p_tclass = SECCLASS_COLUMN;
		*p_perms = __tuple_perms_to_common_perms(perms);
	}
}

static void __check_pg_authid(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
							  uint16 *p_tclass, uint32 *p_perms, char **p_objname)
{
	Form_pg_authid pgauthid = (Form_pg_authid) GETSTRUCT(tuple);

	*p_tclass = SECCLASS_DATABASE;
	*p_perms = __tuple_perms_to_common_perms(perms);
	*p_objname = NameStr(pgauthid->rolname);
}

static void __check_pg_database(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
								uint16 *p_tclass, uint32 *p_perms, char **p_objname)
{
	Form_pg_database pgdatabase = (Form_pg_database) GETSTRUCT(tuple);

	*p_tclass = SECCLASS_DATABASE;
	*p_perms = __tuple_perms_to_common_perms(perms);
	*p_objname = NameStr(pgdatabase->datname);
}

static void __check_pg_largeobject(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
								   uint16 *p_tclass, uint32 *p_perms, char **p_objname)
{
	char buffer[64];

	snprintf(buffer, sizeof(buffer), "blob:%u",
			 ((Form_pg_largeobject) GETSTRUCT(tuple))->loid);
	*p_tclass = SECCLASS_BLOB;
	*p_perms = __tuple_perms_to_common_perms(perms);
	*p_objname = pstrdup(buffer);
}

static void __check_pg_proc(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
							uint16 *p_tclass, uint32 *p_perms, char **p_objname)
{
	Form_pg_proc pgproc = (Form_pg_proc) GETSTRUCT(tuple);

	*p_tclass = SECCLASS_PROCEDURE;
	*p_perms = __tuple_perms_to_common_perms(perms);
	*p_objname = NameStr(pgproc->proname);
}

static void __check_pg_relation(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
								uint16 *p_tclass, uint32 *p_perms, char **p_objname)
{
	Form_pg_class pgclass = (Form_pg_class) GETSTRUCT(tuple);

	if (pgclass->relkind == RELKIND_RELATION) {
		*p_objname = NameStr(pgclass->relname);
		*p_tclass = SECCLASS_TABLE;
		*p_perms = __tuple_perms_to_common_perms(perms);
	} else {
		*p_objname = NameStr(pgclass->relname);
	}
}

static int __check_tuple_perms(Oid tableoid, TupleDesc tdesc, HeapTuple tuple,
							   uint32 perms, char **audit)
{
	uint16 tclass = SECCLASS_TUPLE;
	char *objname = NULL;
	int rc;

	switch (tableoid) {
	case AggregateRelationId:		/* pg_aggregate */
		__check_pg_aggregate(tdesc, tuple, perms, &tclass, &perms, &objname);
		break;
	case AuthIdRelationId:			/* pg_authid */
		__check_pg_authid(tdesc, tuple, perms, &tclass, &perms, &objname);
		break;
	case DatabaseRelationId:		/* pg_database */
		__check_pg_database(tdesc, tuple, perms, &tclass, &perms, &objname);
		break;
	case RelationRelationId:		/* pg_class */	
		__check_pg_relation(tdesc, tuple, perms, &tclass, &perms, &objname);
		break;
	case AttributeRelationId:		/* pg_attribute */
		__check_pg_attribute(tdesc, tuple, perms, &tclass, &perms, &objname);
		break;
	case ProcedureRelationId:		/* pg_proc */
		__check_pg_proc(tdesc, tuple, perms, &tclass, &perms, &objname);
		break;
	case LargeObjectRelationId:		/* pg_largeobject */
		__check_pg_largeobject(tdesc, tuple, perms, &tclass, &perms, &objname);
		break;
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

void sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, uint32 perms)
{
	char *audit;
	int rc;

	rc = __check_tuple_perms(RelationGetRelid(rel),
							 RelationGetDescr(rel),
							 tuple,
							 perms,
							 &audit);
	sepgsql_audit(rc, audit);
}

psid sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple) {
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

	case AuthIdRelationId:
		tcon = sepgsqlGetDatabasePsid();
		tclass = SECCLASS_DATABASE;
		break;

	case RelationRelationId:
		tcon = sepgsqlGetDatabasePsid();
		tclass = SECCLASS_TABLE;
		break;

	case AttributeRelationId: {
		tclass = SECCLASS_COLUMN;
		if (IsBootstrapProcessingMode()
			&& (RelationGetRelid(rel) == TypeRelationId ||
				RelationGetRelid(rel) == ProcedureRelationId ||
				RelationGetRelid(rel) == AttributeRelationId ||
				RelationGetRelid(rel) == ProcedureRelationId)) {
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

	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("modifying pg_selinux is never allowed");

	icon = sepgsqlComputeImplicitContext(rel, tuple);
	econ = HeapTupleGetSecurity(tuple);
	perms = TUPLE__INSERT;
	if (has_returning)
		perms |= TUPLE__SELECT;
	if (icon != econ)
		perms |= TUPLE__RELABELFROM;

	/* 1. implicit labeling */
	HeapTupleSetSecurity(tuple, icon);
	sepgsqlCheckTuplePerms(rel, tuple, perms);

	/* 2. explicit labeling, if necessary */
	if (econ != InvalidOid && icon != econ) {
		HeapTupleSetSecurity(tuple, econ);
		sepgsqlCheckTuplePerms(rel, tuple, TUPLE__RELABELTO);
	}
}

void sepgsqlExecUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup, bool has_returning)
{
	psid ocon, ncon;
	uint32 perms;

	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("modifying pg_selinux is never allowed");

	ocon = HeapTupleGetSecurity(oldtup);
	ncon = HeapTupleGetSecurity(newtup);
	if (ncon == InvalidOid) {
		/* no explicit updating on security_context */
		ncon = ocon;
		HeapTupleSetSecurity(newtup, ocon);
	}

	if (ocon != ncon) {
		/* relabeling happen */
		perms = TUPLE__RELABELTO;
		if (has_returning)
			perms |= TUPLE__SELECT;
		sepgsqlCheckTuplePerms(rel, newtup, perms);
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
	HeapTupleSetSecurity(tuple, sepgsqlComputeImplicitContext(rel, tuple));
}

void sepgsqlHeapUpdate(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	psid newcon, oldcon;

	oldcon = HeapTupleGetSecurity(oldtup);
	newcon = HeapTupleGetSecurity(newtup);

	if (newcon == InvalidOid)
		HeapTupleSetSecurity(newtup, oldcon);
}
