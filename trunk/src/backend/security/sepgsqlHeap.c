/*
 * src/backend/security/sepgsqlHeap.c
 *   SE-PostgreSQL heap modification hooks
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "catalog/indexing.h"
#include "catalog/pg_am.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_listener.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_pltemplate.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_tablespace.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "catalog/pg_selinux.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "security/sepgsql_internal.h"
#include "utils/fmgroids.h"
#include "utils/typcache.h"

/*
 * If we have to refere a object which is newly inserted or updated
 * in the same command, SearchSysCache() returns NULL because it use
 * SnapshowNow internally. The followings are fallback routine to
 * avoid a failed cache lookup.
 */
static HeapTuple __scanRelationSysTbl(Oid relid)
{
	Relation pg_class_desc;
	SysScanDesc pg_class_scan;
	ScanKeyData skey;
	HeapTuple tuple;

	pg_class_desc = heap_open(RelationRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));

	pg_class_scan = systable_beginscan(pg_class_desc, ClassOidIndexId,
									   true, SnapshotSelf, 1, &skey);
	tuple = systable_getnext(pg_class_scan);
	if (HeapTupleIsValid(tuple))
		tuple = heap_copytuple(tuple);
	systable_endscan(pg_class_scan);
	heap_close(pg_class_desc, AccessShareLock);

	return tuple;
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

static char *__tuple_system_object_name(Oid relid, HeapTuple tuple)
{
	char buffer[NAMEDATALEN];
	char *oname = NULL;

	switch (relid) {
	case AccessMethodRelationId:
		oname = NameStr(((Form_pg_am) GETSTRUCT(tuple))->amname);
		break;
	case AttributeRelationId:
		oname = NameStr(((Form_pg_attribute) GETSTRUCT(tuple))->attname);
		break;
	case AuthIdRelationId:
		oname = NameStr(((Form_pg_authid) GETSTRUCT(tuple))->rolname);
		break;
	case RelationRelationId:
		oname = NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname);
		break;
	case ConstraintRelationId:
		oname = NameStr(((Form_pg_constraint) GETSTRUCT(tuple))->conname);
		break;
	case ConversionRelationId:
		oname = NameStr(((Form_pg_conversion) GETSTRUCT(tuple))->conname);
		break;
	case DatabaseRelationId:
		oname = NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname);
		break;
	case LanguageRelationId:
		oname = NameStr(((Form_pg_language) GETSTRUCT(tuple))->lanname);
		break;
	case LargeObjectRelationId: {
		Form_pg_largeobject lobj = (Form_pg_largeobject) GETSTRUCT(tuple);
		snprintf(buffer, sizeof(buffer), "loid:%u", lobj->loid);
		break;
	}
	case ListenerRelationId:
		oname = NameStr(((Form_pg_listener) GETSTRUCT(tuple))->relname);
		break;
	case NamespaceRelationId:
		oname = NameStr(((Form_pg_namespace) GETSTRUCT(tuple))->nspname);
		break;
	case OperatorClassRelationId:
		oname = NameStr(((Form_pg_opclass) GETSTRUCT(tuple))->opcname);
		break;
	case OperatorRelationId:
		oname = NameStr(((Form_pg_operator) GETSTRUCT(tuple))->oprname);
		break;
	case PLTemplateRelationId:
		oname = NameStr(((Form_pg_pltemplate) GETSTRUCT(tuple))->tmplname);
		break;
	case ProcedureRelationId:
		oname = NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname);
		break;
	case RewriteRelationId:
		oname = NameStr(((Form_pg_rewrite) GETSTRUCT(tuple))->rulename);
		break;
	case TableSpaceRelationId:
		oname = NameStr(((Form_pg_tablespace) GETSTRUCT(tuple))->spcname);
		break;
	case TriggerRelationId:
		oname = NameStr(((Form_pg_trigger) GETSTRUCT(tuple))->tgname);
		break;
	case TypeRelationId:
		oname = NameStr(((Form_pg_type) GETSTRUCT(tuple))->typname);
		break;
	}
	return oname;
}

static void __check_pg_attribute(TupleDesc tdesc, HeapTuple tuple, uint32 perms,
								 uint16 *p_tclass, uint32 *p_perms)
{
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);
	Form_pg_class pgclass;
	HeapTuple exttup;
	bool use_syscache = true;

	*p_perms = __tuple_perms_to_common_perms(perms);
	*p_tclass = SECCLASS_COLUMN;

	if (IsBootstrapProcessingMode()) {
		char *tblname = NULL;
		switch (attr->attrelid) {
		case TypeRelationId:		tblname = "pg_type"; break;
		case ProcedureRelationId:	tblname = "pg_proc"; break;
		case AttributeRelationId:	tblname = "pg_attribute"; break;
		case RelationRelationId:	tblname = "pg_class"; break;
		}
		if (tblname) {
			psid tblcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
												sepgsqlGetDatabasePsid(),
												SECCLASS_TABLE);
			sepgsql_avc_permission(sepgsqlGetClientPsid(),
								   tblcon,
								   SECCLASS_TABLE,
								   TABLE__SETATTR,
								   tblname);
			return;
		}
	}
	exttup = SearchSysCache(RELOID, ObjectIdGetDatum(attr->attrelid), 0, 0, 0);
	if (!HeapTupleIsValid(exttup)) {
		use_syscache = false;
		exttup = __scanRelationSysTbl(attr->attrelid);
		if (!HeapTupleIsValid(exttup))
			selerror("cache lookup failed for relation %u", attr->attrelid);
	}
	pgclass = (Form_pg_class) GETSTRUCT(exttup);
	if (pgclass->relkind == RELKIND_RELATION) {
		if (perms & ~(TUPLE__INSERT|TUPLE__DELETE)) {
			sepgsql_avc_permission(sepgsqlGetClientPsid(),
								   HeapTupleGetSecurity(exttup),
								   SECCLASS_TABLE,
								   TABLE__SETATTR,
								   NameStr(pgclass->relname));
		}
	} else {
		*p_tclass = SECCLASS_DATABASE;
	}
	if (use_syscache)
		ReleaseSysCache(exttup);
}

static int __check_tuple_perms(Oid tableoid, TupleDesc tdesc, HeapTuple tuple,
							   uint32 perms, char **audit)
{
	uint16 tclass = SECCLASS_TUPLE;
	char *objname = __tuple_system_object_name(tableoid, tuple);
	int rc;

	switch (tableoid) {
	case AuthIdRelationId:      /* pg_authid */
	case TypeRelationId:
		perms = __tuple_perms_to_common_perms(perms);
		tclass = SECCLASS_DATABASE;
		break;

	case DatabaseRelationId:
		perms = __tuple_perms_to_common_perms(perms);
		tclass = SECCLASS_DATABASE;
		break;

	case RelationRelationId: {
		Form_pg_class pgclass = (Form_pg_class) GETSTRUCT(tuple);
		perms = __tuple_perms_to_common_perms(perms);
		tclass = (pgclass->relkind == RELKIND_RELATION
				  ? SECCLASS_TABLE
				  : SECCLASS_DATABASE);
		break;
	}
	case AttributeRelationId:		/* pg_attribute */
		__check_pg_attribute(tdesc, tuple, perms, &tclass, &perms);
		break;

	case ProcedureRelationId:
		perms = __tuple_perms_to_common_perms(perms);
		tclass = SECCLASS_PROCEDURE;
		break;

	case LargeObjectRelationId:
		perms = __tuple_perms_to_common_perms(perms);
		tclass = SECCLASS_BLOB;
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

bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, uint32 perms, bool abort)
{
	char *audit;
	int rc;

	rc = __check_tuple_perms(RelationGetRelid(rel),
							 RelationGetDescr(rel),
							 tuple,
							 perms,
							 &audit);
	sepgsql_audit((abort ? rc : 0), audit);

	return (rc==0 ? true : false);
}

psid sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple) {
	uint16 tclass;
	psid tcon;
	HeapTuple exttup;

	switch (RelationGetRelid(rel)) {
		/* database system object */
	case AuthIdRelationId:
	case TypeRelationId:
		tcon = sepgsqlGetDatabasePsid();
		tclass = SECCLASS_DATABASE;
		break;

	case DatabaseRelationId:
		tcon = sepgsqlGetServerPsid();
		tclass = SECCLASS_DATABASE;
		break;

	case RelationRelationId: {
		Form_pg_class pgclass = (Form_pg_class) GETSTRUCT(tuple);
		tcon = sepgsqlGetDatabasePsid();
		tclass = (pgclass->relkind == RELKIND_RELATION
				  ? SECCLASS_TABLE
				  : SECCLASS_DATABASE);
		break;
	}
	case AttributeRelationId: {
		Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);
		Form_pg_class pgclass;
		bool use_syscache = true;

		/* special case in bootstraping mode */
		if (IsBootstrapProcessingMode()
			&& (attr->attrelid == TypeRelationId ||
				attr->attrelid == ProcedureRelationId ||
				attr->attrelid == AttributeRelationId ||
				attr->attrelid == RelationRelationId)) {
			tcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetDatabasePsid(),
										 SECCLASS_TABLE);
			tclass = SECCLASS_COLUMN;
			break;
		}

		exttup = SearchSysCache(RELOID,
								ObjectIdGetDatum(attr->attrelid),
								0, 0, 0);
		if (!HeapTupleIsValid(exttup)) {
			use_syscache = false;
			exttup = __scanRelationSysTbl(attr->attrelid);
			if (!HeapTupleIsValid(exttup))
				selerror("cache lookup failed for relation %u %s",
						 attr->attrelid, NameStr(attr->attname));
		}
		pgclass = (Form_pg_class) GETSTRUCT(exttup);
		tcon = HeapTupleGetSecurity(exttup);
		tclass = (pgclass->relkind == RELKIND_RELATION
				  ? SECCLASS_COLUMN
				  : SECCLASS_TABLE);
		if (use_syscache)
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
	return sepgsql_avc_createcon(sepgsqlGetClientPsid(), tcon, tclass);
}

void sepgsqlExecInsert(Relation rel, HeapTuple tuple, bool has_returning)
{
	psid icon, econ;
	uint32 perms = TUPLE__INSERT;

	if (RelationGetRelid(rel) == SelinuxRelationId)
		selerror("modifying pg_selinux is never allowed");

	icon = sepgsqlComputeImplicitContext(rel, tuple);
	econ = HeapTupleGetSecurity(tuple);
	if (has_returning)
		perms |= TUPLE__SELECT;
	if (econ != InvalidOid && icon != econ)
		perms |= TUPLE__RELABELFROM;

	/* 1. implicit labeling */
	HeapTupleSetSecurity(tuple, icon);
	sepgsqlCheckTuplePerms(rel, tuple, perms, true);

	/* 2. explicit labeling, if necessary */
	if (econ != InvalidOid && icon != econ) {
		HeapTupleSetSecurity(tuple, econ);
		sepgsqlCheckTuplePerms(rel, tuple, TUPLE__RELABELTO, true);
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
		sepgsqlCheckTuplePerms(rel, newtup, perms, true);
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
