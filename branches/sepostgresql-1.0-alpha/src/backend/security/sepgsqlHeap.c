/*
 * src/backend/security/sepgsqlHeap.c
 *   SE-PostgreSQL heap modification hooks
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "security/sepgsql_internal.h"
#include "utils/fmgroids.h"
#include "utils/typcache.h"

static bool __check_tuple_perms(Oid tableoid, TupleDesc tdesc,
								HeapTuple tuple, HeapTuple oldtup,
                                uint32 perms, bool abort);

static bool __is_system_object_relation(Oid relid)
{
	static Oid latest_relid = InvalidOid;
	static Oid latest_relns = InvalidOid;
	HeapTuple tuple;

retry:
	if (latest_relid == relid) {
		if (IsSystemNamespace(latest_relns))
			return true;
		return false;
	}

	tuple = SearchSysCache(RELOID, ObjectIdGetDatum(relid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation %u", relid);
	latest_relid = relid;
	latest_relns = ((Form_pg_class) GETSTRUCT(tuple))->relnamespace;
	ReleaseSysCache(tuple);

	goto retry;
}

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
		oname = pstrdup(buffer);
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
								 uint32 *p_perms, uint16 *p_tclass)
{
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(newtup);
	Form_pg_class pgclass;
	HeapTuple exttup;
	bool use_syscache = true;

	*p_perms = __tuple_perms_to_common_perms(*p_perms);
	*p_tclass = SECCLASS_COLUMN;

	if (IsBootstrapProcessingMode()) {
		char *tblname = NULL;
		switch (attr->attrelid) {
		case TypeRelationId:		tblname = "pg_type";		break;
		case ProcedureRelationId:	tblname = "pg_proc";		break;
		case AttributeRelationId:	tblname = "pg_attribute";	break;
		case RelationRelationId:	tblname = "pg_class";		break;
		}
		if (tblname)
			return;
	}
	exttup = SearchSysCache(RELOID, ObjectIdGetDatum(attr->attrelid), 0, 0, 0);
	if (!HeapTupleIsValid(exttup)) {
		use_syscache = false;
		exttup = __scanRelationSysTbl(attr->attrelid);
		if (!HeapTupleIsValid(exttup))
			selerror("cache lookup failed for relation %u", attr->attrelid);
	}
	pgclass = (Form_pg_class) GETSTRUCT(exttup);
	if (pgclass->relkind != RELKIND_RELATION)
		*p_tclass = SECCLASS_DATABASE;
	if (use_syscache)
		ReleaseSysCache(exttup);
}

static void __check_pg_largeobject(TupleDesc tdesc, HeapTuple tuple, HeapTuple oldtup,
								   uint32 *p_perms, uint16 *p_tclass)
{
	Oid loid = ((Form_pg_largeobject) GETSTRUCT(tuple))->loid;
	int32 pageno = ((Form_pg_largeobject) GETSTRUCT(tuple))->pageno;
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	uint32 perms = 0;
	bool found = false;

	perms |= (*p_perms & TUPLE__SELECT ? BLOB__GETATTR : 0);
	perms |= (*p_perms & TUPLE__UPDATE ? BLOB__SETATTR : 0);
	perms |= (*p_perms & BLOB__READ    ? BLOB__READ    : 0);
	perms |= (*p_perms & BLOB__WRITE   ? BLOB__WRITE   : 0);

	if (*p_perms & TUPLE__INSERT) {
		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(loid));
		rel = heap_open(LargeObjectRelationId, AccessShareLock);
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		if (HeapTupleIsValid(systable_getnext(sd)))
            found = true;
		systable_endscan(sd);
		heap_close(rel, NoLock);
		perms |= (found ? BLOB__WRITE : BLOB__CREATE);

	} else if (*p_perms & TUPLE__DELETE) {
		HeapTuple exttup;

		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(loid));
		rel = heap_open(LargeObjectRelationId, AccessShareLock);
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		while ((exttup = systable_getnext(sd))) {
			if (pageno != ((Form_pg_largeobject) GETSTRUCT(exttup))->pageno) {
				found = true;
				break;
			}
		}
		systable_endscan(sd);
		heap_close(rel, NoLock);
		perms |= (found ? BLOB__WRITE : BLOB__DROP);
	}
	*p_tclass = SECCLASS_BLOB;
	*p_perms = perms;
}

static void __check_pg_proc(TupleDesc tdesc, HeapTuple tuple, HeapTuple oldtup,
							uint32 *p_perms, uint16 *p_tclass)
{
	uint32 perms = __tuple_perms_to_common_perms(*p_perms);
	Form_pg_proc proc = (Form_pg_proc) GETSTRUCT(tuple);

	if (proc->prolang == ClanguageId) {
		bool verify_shlib = false;
		Datum obin, nbin;
		bool isnull;

		nbin = heap_getattr(tuple, Anum_pg_proc_probin, tdesc, &isnull);
		if (!isnull) {
			if (perms & PROCEDURE__CREATE) {
				verify_shlib = true;
			} else if (oldtup) {
				obin = heap_getattr(oldtup, Anum_pg_proc_probin, tdesc, &isnull);
				if (isnull || DatumGetBool(DirectFunctionCall2(textne, obin, nbin)))
					verify_shlib = true;
			}

			if (verify_shlib) {
				char *filename;
				security_context_t filecon;
				Datum filecon_psid;

				/* <client type> <-- database:module_install --> <database type> */
				sepgsql_avc_permission(sepgsqlGetClientPsid(),
									   sepgsqlGetDatabasePsid(),
									   SECCLASS_DATABASE,
									   DATABASE__INSTALL_MODULE,
									   NULL);

				/* <client type> <-- database:module_install --> <file type> */
				filename = DatumGetCString(DirectFunctionCall1(textout, nbin));
				filename = sepgsql_expand_dynamic_library_name(filename);
				if (getfilecon(filename, &filecon) < 1)
					selerror("could not obtain the security context of '%s'", filename);
				PG_TRY();
				{
					filecon_psid = DirectFunctionCall1(psid_in, CStringGetDatum(filecon));
				}
				PG_CATCH();
				{
					freecon(filecon);
					PG_RE_THROW();
				}
				PG_END_TRY();
				freecon(filecon);

				sepgsql_avc_permission(sepgsqlGetClientPsid(),
									   DatumGetObjectId(filecon_psid),
									   SECCLASS_DATABASE,
									   DATABASE__INSTALL_MODULE,
									   filename);
			}
		}
	}
	*p_perms = perms;
	*p_tclass = SECCLASS_PROCEDURE;
}

static void __check_pg_relation(TupleDesc tdesc, HeapTuple tuple, HeapTuple oldtup,
								uint32 *p_perms, uint16 *p_tclass)
{
	Form_pg_class pgclass = (Form_pg_class) GETSTRUCT(tuple);
	*p_tclass = (pgclass->relkind == RELKIND_RELATION
				 ? SECCLASS_TABLE
				 : SECCLASS_DATABASE);
	*p_perms = __tuple_perms_to_common_perms(*p_perms);

	/*
	 * When you drop a table, you have to have a permission to delete tuples.
	 */
	if (*p_tclass == SECCLASS_TABLE && (*p_perms & TABLE__DROP)) {
		Oid tableoid;
		Relation rel;
		HeapScanDesc scan;
		HeapTuple exttup;

		tableoid = HeapTupleGetOid(tuple);
		rel = heap_open(tableoid, AccessShareLock);
		scan = heap_beginscan(rel, SnapshotNow, 0, NULL);
		while ((exttup = heap_getnext(scan, ForwardScanDirection)) != NULL) {
			__check_tuple_perms(tableoid, RelationGetDescr(rel),
								exttup, NULL, TUPLE__DELETE, true);
		}
		heap_endscan(scan);
		heap_close(rel, AccessShareLock);
	}
}

static bool __check_tuple_perms(Oid tableoid, TupleDesc tdesc, HeapTuple tuple, HeapTuple oldtup,
								uint32 perms, bool abort)
{
	uint16 tclass;
	bool rc = true;

	Assert(tuple != NULL);

	switch (tableoid) {
	case DatabaseRelationId:    /* pg_database */
	case TypeRelationId:        /* pg_type */
		perms = __tuple_perms_to_common_perms(perms);
		tclass = SECCLASS_DATABASE;
		break;

	case RelationRelationId:
		__check_pg_relation(tdesc, tuple, oldtup, &perms, &tclass);
		break;

	case AttributeRelationId:		/* pg_attribute */
		__check_pg_attribute(tdesc, tuple, oldtup, &perms, &tclass);
		break;

	case ProcedureRelationId:
		__check_pg_proc(tdesc, tuple, oldtup, &perms, &tclass);
		break;

	case LargeObjectRelationId:
		__check_pg_largeobject(tdesc, tuple, oldtup, &perms, &tclass);
		break;

	default:
		if (__is_system_object_relation(tableoid)) {
			perms = __tuple_perms_to_common_perms(perms);
			tclass = SECCLASS_DATABASE;
		} else {
			tclass = SECCLASS_TUPLE;
		}
		break;
	}

	if (perms) {
		char *audit;
		char *object_name = __tuple_system_object_name(tableoid, tuple);
		rc = sepgsql_avc_permission_noaudit(sepgsqlGetClientPsid(),
											HeapTupleGetSecurity(tuple),
											tclass,
											perms,
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

	rc = __check_tuple_perms(tableoid, tdesc, &tuple, NULL, perms, abort);

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

bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple oldtup, uint32 perms, bool abort)
{
	return __check_tuple_perms(RelationGetRelid(rel),
							   RelationGetDescr(rel),
							   tuple,
							   oldtup,
							   perms,
							   abort);
}

psid sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple) {
	uint16 tclass;
	psid tcon;
	HeapTuple exttup;

	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:    /* pg_database */
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

	case TypeRelationId:        /* pg_type */
		tclass = SECCLASS_DATABASE;
		tcon = sepgsqlGetDatabasePsid();
		break;

	default:
		if (__is_system_object_relation(RelationGetRelid(rel))) {
			tclass = SECCLASS_DATABASE;
			tcon = sepgsqlGetDatabasePsid();
		} else {
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
