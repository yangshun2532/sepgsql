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

static void __check_pg_attribute(TupleDesc tdesc, HeapTuple newtup, HeapTuple oldtup,
								 uint32 *p_nperms, uint32 *p_operms, uint16 *p_tclass)
{
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(newtup);
	Form_pg_class pgclass;
	HeapTuple exttup;
	uint32 perms = *p_nperms;
	bool use_syscache = true;

	*p_nperms = __tuple_perms_to_common_perms(*p_nperms);
	*p_operms = __tuple_perms_to_common_perms(*p_operms);
	*p_tclass = SECCLASS_COLUMN;

	if (IsBootstrapProcessingMode()) {
		char *tblname = NULL;
		switch (attr->attrelid) {
		case TypeRelationId:		tblname = "pg_type";		break;
		case ProcedureRelationId:	tblname = "pg_proc";		break;
		case AttributeRelationId:	tblname = "pg_attribute";	break;
		case RelationRelationId:	tblname = "pg_class";		break;
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
		if (perms & (TUPLE__INSERT | TUPLE__DELETE)) {
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

static bool __check_tuple_perms(Oid tableoid, TupleDesc tdesc,
								HeapTuple newtup, uint32 nperms,
								HeapTuple oldtup, uint32 operms, bool abort)
{
	uint16 tclass;
	char *object_name;
	char *audit;
	bool rc = true;

	Assert(newtup != NULL);

	switch (tableoid) {
	case AuthIdRelationId:      /* pg_authid */
	case TypeRelationId:
		nperms = __tuple_perms_to_common_perms(nperms);
		operms = __tuple_perms_to_common_perms(operms);
		tclass = SECCLASS_DATABASE;
		break;

	case DatabaseRelationId:
		nperms = __tuple_perms_to_common_perms(nperms);
		operms = __tuple_perms_to_common_perms(operms);
		tclass = SECCLASS_DATABASE;
		break;

	case RelationRelationId: {
		Form_pg_class pgclass = (Form_pg_class) GETSTRUCT(newtup);
		nperms = __tuple_perms_to_common_perms(nperms);
		operms = __tuple_perms_to_common_perms(operms);
		tclass = (pgclass->relkind == RELKIND_RELATION
				  ? SECCLASS_TABLE
				  : SECCLASS_DATABASE);
		break;
	}
	case AttributeRelationId:		/* pg_attribute */
		__check_pg_attribute(tdesc, newtup, oldtup, &nperms, &operms, &tclass);
		break;

	case ProcedureRelationId:
		nperms = __tuple_perms_to_common_perms(nperms);
		operms = __tuple_perms_to_common_perms(operms);
		tclass = SECCLASS_PROCEDURE;
		break;

	case LargeObjectRelationId:
		nperms = __tuple_perms_to_common_perms(nperms);
		operms = __tuple_perms_to_common_perms(operms);
		tclass = SECCLASS_BLOB;
		break;

	default:
		tclass = SECCLASS_TUPLE;
		break;
	}

	if (operms) {
		Assert(oldtup != NULL);
		object_name = __tuple_system_object_name(tableoid, oldtup);
		rc = sepgsql_avc_permission_noaudit(sepgsqlGetClientPsid(),
											HeapTupleGetSecurity(oldtup),
											tclass,
											operms,
											&audit,
											object_name);
		sepgsql_audit(abort ? rc : true, audit);
	}
	if (rc && nperms) {
		object_name = __tuple_system_object_name(tableoid, newtup);
		rc = sepgsql_avc_permission_noaudit(sepgsqlGetClientPsid(),
											HeapTupleGetSecurity(newtup),
											tclass,
											nperms,
											&audit,
											object_name);
		sepgsql_audit(abort ? rc : true, audit);
	}
	return rc;
}

static bool __sepgsql_tuple_perms(Oid tableoid, HeapTupleHeader rec, uint32 perms, bool abort)
{
	HeapTupleData tuple;
	TupleDesc tdesc;
	bool rc;

	tdesc = lookup_rowtype_tupdesc(HeapTupleHeaderGetTypeId(rec),
								   HeapTupleHeaderGetTypMod(rec));
	tuple.t_len = HeapTupleHeaderGetDatumLength(rec);
    ItemPointerSetInvalid(&(tuple.t_self));
    tuple.t_tableOid = tableoid;
    tuple.t_data = rec;

	rc = __check_tuple_perms(tableoid, tdesc, &tuple, perms, NULL, 0, abort);

	ReleaseTupleDesc(tdesc);

	return rc;
}

Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS)
{
	Oid tableoid = PG_GETARG_OID(0);
	HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(1);
	uint32 perms = PG_GETARG_UINT32(2);
	bool rc;

	rc = __sepgsql_tuple_perms(tableoid, rec, perms, false);

	PG_RETURN_BOOL(rc);
}

Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS)
{
	Oid tableoid = PG_GETARG_OID(0);
	HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(1);
	uint32 perms = PG_GETARG_UINT32(2);

	PG_RETURN_BOOL(__sepgsql_tuple_perms(tableoid, rec, perms, true));
}

bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple newtup, uint32 nperms,
							HeapTuple oldtup, uint32 operms, bool abort)
{
	return __check_tuple_perms(RelationGetRelid(rel),
							   RelationGetDescr(rel),
							   newtup, nperms,
							   oldtup, operms,
							   abort);
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
