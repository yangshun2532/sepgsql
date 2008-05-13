/*
 * src/backend/security/sepgsqlPerms.c
 *   SE-PostgreSQL permission checking functions
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "catalog/catalog.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/pgace.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include "utils/tqual.h"
#include "utils/typcache.h"

/*
 * If we have to refere a object which is newly inserted or updated
 * in the same command, SearchSysCache() returns NULL because it use
 * SnapshowNow internally. The followings are fallback routine to
 * avoid a failed cache lookup.
 */
static Oid __lookupRelationForm(Oid relid, Form_pg_class classForm) {
	Relation rel;
	SysScanDesc scan;
	ScanKeyData skey;
	HeapTuple tuple;
	Oid t_security;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		if (classForm)
			memcpy(classForm, GETSTRUCT(tuple), sizeof(FormData_pg_class));
		t_security = HeapTupleGetSecurity(tuple);
		ReleaseSysCache(tuple);
		return t_security;
	}

	rel = heap_open(RelationRelationId, AccessShareLock);
	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));
	scan = systable_beginscan(rel, ClassOidIndexId,
							  true, SnapshotSelf, 1, &skey);
	tuple = systable_getnext(scan);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", relid);

	if (classForm)
		memcpy(classForm, GETSTRUCT(tuple), sizeof(FormData_pg_class));
	t_security = HeapTupleGetSecurity(tuple);

	systable_endscan(scan);
	heap_close(rel, AccessShareLock);

	return t_security;
}

static uint32 __sepgsql_perms_to_common_perms(uint32 perms) {
	uint32 __perms = 0;

	Assert((perms & ~SEPGSQL_PERMS_ALL) == 0);
	__perms |= (perms & SEPGSQL_PERMS_USE		? COMMON_DATABASE__GETATTR : 0);
	__perms |= (perms & SEPGSQL_PERMS_SELECT	? COMMON_DATABASE__GETATTR : 0);
	__perms |= (perms & SEPGSQL_PERMS_UPDATE	? COMMON_DATABASE__SETATTR : 0);
	__perms |= (perms & SEPGSQL_PERMS_INSERT	? COMMON_DATABASE__CREATE  : 0);
	__perms |= (perms & SEPGSQL_PERMS_DELETE	? COMMON_DATABASE__DROP    : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELFROM ? COMMON_DATABASE__RELABELFROM : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELTO	? COMMON_DATABASE__RELABELTO : 0);

	return __perms;
}

static uint32 __sepgsql_perms_to_tuple_perms(uint32 perms) {
	uint32 __perms = 0;

	Assert((perms & ~SEPGSQL_PERMS_ALL) == 0);
	__perms |= (perms & SEPGSQL_PERMS_USE		? DB_TUPLE__USE : 0);
	__perms |= (perms & SEPGSQL_PERMS_SELECT	? DB_TUPLE__SELECT : 0);
	__perms |= (perms & SEPGSQL_PERMS_UPDATE	? DB_TUPLE__UPDATE : 0);
	__perms |= (perms & SEPGSQL_PERMS_INSERT	? DB_TUPLE__INSERT : 0);
	__perms |= (perms & SEPGSQL_PERMS_DELETE	? DB_TUPLE__DELETE : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELFROM ? DB_TUPLE__RELABELFROM : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELTO	? DB_TUPLE__RELABELTO : 0);

	return __perms;
}

char *sepgsqlGetTupleName(Oid relid, HeapTuple tuple, NameData *name)
{
	switch (relid) {
	case AttributeRelationId: {
		Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);
		HeapTuple reltup;

		if (IsBootstrapProcessingMode()) {
			strncpy(NameStr(*name),
					NameStr(attr->attname),
					NAMEDATALEN);
			return NameStr(*name);
		}
		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(attr->attrelid),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup)) {
			strncpy(NameStr(*name),
					NameStr(attr->attname),
					NAMEDATALEN);
			return NameStr(*name);
		}
		snprintf(NameStr(*name), NAMEDATALEN, "%s.%s",
				 NameStr(((Form_pg_class) GETSTRUCT(reltup))->relname),
				 NameStr(attr->attname));
		ReleaseSysCache(reltup);
		return NameStr(*name);
	}
	case AuthIdRelationId: {
		strncpy(NameStr(*name),
				NameStr(((Form_pg_authid) GETSTRUCT(tuple))->rolname),
				NAMEDATALEN);
		return NameStr(*name);
	}
	case RelationRelationId: {
		strncpy(NameStr(*name),
				NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname),
				NAMEDATALEN);
		return NameStr(*name);
	}
	case DatabaseRelationId: {
		strncpy(NameStr(*name),
				NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname),
				NAMEDATALEN);
		return NameStr(*name);
	}
	case LargeObjectRelationId: {
		snprintf(NameStr(*name), NAMEDATALEN, "loid:%u",
				 ((Form_pg_largeobject) GETSTRUCT(tuple))->loid);
		return NameStr(*name);
	}
	case ProcedureRelationId: {
		strncpy(NameStr(*name),
				NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname),
				NAMEDATALEN);
		return NameStr(*name);
	}
	case TriggerRelationId: {
		strncpy(NameStr(*name),
				NameStr(((Form_pg_trigger) GETSTRUCT(tuple))->tgname),
				NAMEDATALEN);
		return NameStr(*name);
	}
	case TypeRelationId: {
		snprintf(NameStr(*name), NAMEDATALEN, "pg_type::%s",
				 NameStr(((Form_pg_type) GETSTRUCT(tuple))->typname));
		return NameStr(*name);
	}
	default:
		if (HeapTupleGetOid(tuple) != InvalidOid) {
			snprintf(NameStr(*name), NAMEDATALEN, "relid:%u,oid:%u",
					 relid, HeapTupleGetOid(tuple));
			return NameStr(*name);
		}
		break;
	}
	return NULL;
}

static void __check_pg_attribute(HeapTuple tuple, HeapTuple oldtup,
								 uint32 *p_perms, uint16 *p_tclass)
{
	Form_pg_attribute attrForm = (Form_pg_attribute) GETSTRUCT(tuple);
	FormData_pg_class classForm;

	switch (attrForm->attrelid) {
    case TypeRelationId:
    case ProcedureRelationId:
    case AttributeRelationId:
    case RelationRelationId:
		/* those are pure relation */
		break;
	default:
		__lookupRelationForm(attrForm->attrelid, &classForm);
		if (classForm.relkind != RELKIND_RELATION) {
			*p_tclass = SECCLASS_DB_TUPLE;
			*p_perms = __sepgsql_perms_to_tuple_perms(*p_perms);
			return;
		}
		break;
	}
	*p_tclass = SECCLASS_DB_COLUMN;
	*p_perms = __sepgsql_perms_to_common_perms(*p_perms);
	if (HeapTupleIsValid(oldtup)) {
		Form_pg_attribute oldForm = (Form_pg_attribute) GETSTRUCT(oldtup);

		if (oldForm->attisdropped != true && attrForm->attisdropped == true)
			*p_perms |= DB_COLUMN__DROP;
	}
}

static void __check_pg_largeobject(HeapTuple tuple, HeapTuple oldtup,
								   uint32 *p_perms, uint16 *p_tclass)
{
	Form_pg_largeobject loForm = (Form_pg_largeobject) GETSTRUCT(tuple);
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple exttup;
	uint32 perms = 0;

	perms |= (*p_perms & SEPGSQL_PERMS_USE    ? DB_BLOB__GETATTR : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_SELECT ? DB_BLOB__GETATTR : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_UPDATE ? DB_BLOB__SETATTR | DB_BLOB__WRITE : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_RELABELFROM ? DB_BLOB__RELABELFROM : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_READ   ? DB_BLOB__READ  : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_WRITE  ? DB_BLOB__WRITE : 0);

	if (*p_perms & SEPGSQL_PERMS_INSERT) {
		perms |= DB_BLOB__SETATTR | DB_BLOB__WRITE;
		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(loForm->loid));
		rel = heap_open(LargeObjectRelationId, AccessShareLock);
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		/* INSERT the first one means create a largeobject */
		exttup = systable_getnext(sd);
		if (!HeapTupleIsValid(exttup)) {
			perms |= DB_BLOB__CREATE;
		} else if (HeapTupleGetSecurity(tuple) != HeapTupleGetSecurity(exttup)) {
			elog(ERROR, "SELinux: inconsistent security context specified");
		}
		systable_endscan(sd);
		heap_close(rel, AccessShareLock);
	}

	if (*p_perms & SEPGSQL_PERMS_DELETE) {
		bool found = false;

		perms |= DB_BLOB__SETATTR | DB_BLOB__WRITE;
		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(loForm->loid));
		rel = heap_open(LargeObjectRelationId, AccessShareLock);
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		while ((exttup = systable_getnext(sd))) {
			int __pageno = ((Form_pg_largeobject) GETSTRUCT(exttup))->pageno;

			if (loForm->pageno != __pageno) {
				found = true;
				break;
			}
		}
		systable_endscan(sd);
		heap_close(rel, AccessShareLock);

		/*
		 * If this tuple is the last one with given large object,
		 * it means to drop the whole of large object.
		 */
		if (!found)
			perms |= DB_BLOB__DROP;
	}

	/*
	 * SE-PostgreSQL does not allow different security contexts are
	 * held in a single large object.
	 */
	if (*p_perms & SEPGSQL_PERMS_RELABELTO) {
		bool found = false;

		perms |= DB_BLOB__RELABELTO;
		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(loForm->loid));
		rel = heap_open(LargeObjectRelationId, AccessShareLock);
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		while ((exttup = systable_getnext(sd))) {
			int __pageno = ((Form_pg_largeobject) GETSTRUCT(exttup))->pageno;

			if (loForm->pageno != __pageno) {
				found = true;
				break;
			}
		}
		systable_endscan(sd);
		heap_close(rel, AccessShareLock);

		if (found)
			elog(ERROR,
				 "SELinux: It's not possible a part of tuples within"
				 " a single large object to have different security context."
				 " You can use lo_set_security() instead.");
	}
	*p_tclass = SECCLASS_DB_BLOB;
	*p_perms = perms;
}

static void __check_pg_proc(HeapTuple tuple, HeapTuple oldtup,
							uint32 *p_perms, uint16 *p_tclass)
{
	uint32 perms = __sepgsql_perms_to_common_perms(*p_perms);
	Form_pg_proc procForm = (Form_pg_proc) GETSTRUCT(tuple);

	if (procForm->prolang == ClanguageId) {
		Datum oldbin, newbin;
		bool isnull, verify = false;

		newbin = SysCacheGetAttr(PROCOID, tuple,
								 Anum_pg_proc_probin, &isnull);
		if (!isnull) {
			if (perms & DB_PROCEDURE__CREATE) {
				verify = true;
			} else if (HeapTupleIsValid(oldtup)) {
				oldbin = SysCacheGetAttr(PROCOID, oldtup,
										 Anum_pg_proc_probin, &isnull);
				if (isnull || DatumGetBool(DirectFunctionCall2(textne, oldbin, newbin)))
					verify = true;
			}

			if (verify) {
				char *filename;
				security_context_t filecon;
				Datum filesid;

				/* <client type> <-- database:module_install --> <database type> */
				sepgsql_avc_permission(sepgsqlGetClientContext(),
									   sepgsqlGetDatabaseContext(),
									   SECCLASS_DB_DATABASE,
									   DB_DATABASE__INSTALL_MODULE,
									   NULL);

				/* <client type> <-- database:module_install --> <file type> */
				filename = DatumGetCString(DirectFunctionCall1(textout, newbin));
				filename = expand_dynamic_library_name(filename);
				if (getfilecon_raw(filename, &filecon) < 0)
					elog(ERROR, "SELinux: could not obtain security context of %s", filename);
				PG_TRY();
				{
					filesid = DirectFunctionCall1(security_label_raw_in,
												  CStringGetDatum(filecon));
				}
				PG_CATCH();
				{
					freecon(filecon);
					PG_RE_THROW();
				}
				PG_END_TRY();
				freecon(filecon);

				sepgsql_avc_permission(sepgsqlGetClientContext(),
									   DatumGetObjectId(filesid),
									   SECCLASS_DB_DATABASE,
									   DB_DATABASE__INSTALL_MODULE,
									   filename);
			}
		}
	}
	*p_perms = perms;
	*p_tclass = SECCLASS_DB_PROCEDURE;
}

static void __check_pg_relation(HeapTuple tuple, HeapTuple oldtup,
								uint32 *p_perms, uint16 *p_tclass)
{
	Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
	if (classForm->relkind == RELKIND_RELATION) {
		*p_tclass = SECCLASS_DB_TABLE;
		*p_perms = __sepgsql_perms_to_common_perms(*p_perms);
	} else {
		*p_tclass = SECCLASS_DB_TUPLE;
		*p_perms = __sepgsql_perms_to_tuple_perms(*p_perms);
	}
}

static bool __check_tuple_perms(Oid tableoid, Oid tcontext, uint32 perms,
								HeapTuple tuple, HeapTuple oldtup, bool abort)
{
	uint16 tclass;
	bool rc = true;

	Assert(tuple != NULL);

	switch (tableoid) {
	case DatabaseRelationId:		/* pg_database */
		perms = __sepgsql_perms_to_common_perms(perms);
		tclass = SECCLASS_DB_DATABASE;
		break;

	case RelationRelationId:		/* pg_class */
		__check_pg_relation(tuple, oldtup, &perms, &tclass);
		break;

	case AttributeRelationId:		/* pg_attribute */
		__check_pg_attribute(tuple, oldtup, &perms, &tclass);
		break;

	case ProcedureRelationId:		/* pg_proc */
		__check_pg_proc(tuple, oldtup, &perms, &tclass);
		break;

	case LargeObjectRelationId:		/* pg_largeobject */
		__check_pg_largeobject(tuple, oldtup, &perms, &tclass);
		break;

	default:
		perms = __sepgsql_perms_to_tuple_perms(perms);
		tclass = SECCLASS_DB_TUPLE;
		break;
	}

	if (perms) {
		NameData name;

		if (abort) {
			sepgsql_avc_permission(sepgsqlGetClientContext(),
								   tcontext,
								   tclass,
								   perms,
								   sepgsqlGetTupleName(tableoid, tuple, &name));
		} else {
			rc = sepgsql_avc_permission_noabort(sepgsqlGetClientContext(),
												tcontext,
												tclass,
												perms,
												sepgsqlGetTupleName(tableoid, tuple, &name));
		}
	}
	return rc;
}

/*
 * MEMO: we cannot obtain system column from RECORD datatype.
 * If those are necesasry, they should be separately delivered. 
 */
Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS)
{
	Oid tableoid = PG_GETARG_OID(0);
	Oid tcontext = PG_GETARG_OID(1);
	uint32 perms = PG_GETARG_UINT32(2);
	HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(3);
	HeapTupleData tuple;

	tuple.t_len = HeapTupleHeaderGetDatumLength(rec);
	ItemPointerSetInvalid(&tuple.t_self);
	tuple.t_tableOid = tableoid;
	tuple.t_data = rec;

	PG_RETURN_BOOL(__check_tuple_perms(tableoid, tcontext, perms, &tuple, NULL, false));
}

Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS)
{
	Oid tableoid = PG_GETARG_OID(0);
	Oid tcontext = PG_GETARG_OID(1);
	uint32 perms = PG_GETARG_UINT32(2);
	HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(3);
	HeapTupleData tuple;

	tuple.t_len = HeapTupleHeaderGetDatumLength(rec);
	ItemPointerSetInvalid(&tuple.t_self);
	tuple.t_tableOid = tableoid;
	tuple.t_data = rec;

	PG_RETURN_BOOL(__check_tuple_perms(tableoid, tcontext, perms, &tuple, NULL, true));
}

bool sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple oldtup, uint32 perms, bool abort)
{
	return __check_tuple_perms(RelationGetRelid(rel),
							   HeapTupleGetSecurity(tuple),
							   perms,
							   tuple,
							   oldtup,
							   abort);
}

Oid sepgsqlComputeImplicitContext(Relation rel, HeapTuple tuple) {
	uint16 tclass;
	Oid tcon;

	switch (RelationGetRelid(rel)) {
	case DatabaseRelationId:		/* pg_database */
		tclass = SECCLASS_DB_DATABASE;
		tcon = sepgsqlGetServerContext();
		break;

	case RelationRelationId: {		/* pg_class */
		Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
		if (classForm->relkind == RELKIND_RELATION) {
			tclass = SECCLASS_DB_TABLE;
			tcon = sepgsqlGetDatabaseContext();
			break;
		}
		tcon = __lookupRelationForm(RelationRelationId, NULL);
		tclass = SECCLASS_DB_TUPLE;
		break;
	}
	case AttributeRelationId: {		/* pg_attribute */
		Form_pg_attribute attrForm = (Form_pg_attribute) GETSTRUCT(tuple);
		FormData_pg_class classForm;

		/* special case in bootstraping mode */
		if (IsBootstrapProcessingMode()
			&& (attrForm->attrelid == TypeRelationId ||
				attrForm->attrelid == ProcedureRelationId ||
				attrForm->attrelid == AttributeRelationId ||
				attrForm->attrelid == RelationRelationId)) {
			tcon = sepgsql_avc_createcon(sepgsqlGetClientContext(),
										 sepgsqlGetDatabaseContext(),
										 SECCLASS_DB_TABLE);
			tclass = SECCLASS_DB_COLUMN;
			break;
		}
		tcon = __lookupRelationForm(attrForm->attrelid, &classForm);
		tclass = (classForm.relkind == RELKIND_RELATION
				  ? SECCLASS_DB_COLUMN
				  : SECCLASS_DB_TUPLE);
		break;
	}
	case ProcedureRelationId:
		tclass = SECCLASS_DB_PROCEDURE;
		tcon = sepgsqlGetDatabaseContext();
		break;

	case LargeObjectRelationId: {		/* pg_largeobject */
		ScanKeyData skey;
		SysScanDesc sd;
		HeapTuple lotup;
		Oid loid, lo_security = InvalidOid;

		loid = ((Form_pg_largeobject) GETSTRUCT(tuple))->loid;
		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(loid));
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		lotup = systable_getnext(sd);
		if (HeapTupleIsValid(lotup))
			lo_security = HeapTupleGetSecurity(lotup);
		systable_endscan(sd);
		/* Inherit previous page's security context */
		if (lo_security != InvalidOid)
			return lo_security;
		/* compute newly created one */
		tclass = SECCLASS_DB_BLOB;
		tcon = sepgsqlGetDatabaseContext();
		break;
	}
	case TypeRelationId:		/* pg_type */
		if (IsBootstrapProcessingMode()) {
			/* special case in early phase */
			tcon = sepgsql_avc_createcon(sepgsqlGetClientContext(),
										 sepgsqlGetDatabaseContext(),
										 SECCLASS_DB_TABLE);
			tclass = SECCLASS_DB_TUPLE;
			break;
		}
	default:
		tclass = SECCLASS_DB_TUPLE;
		tcon = __lookupRelationForm(RelationGetRelid(rel), NULL);
		break;
	}
	return sepgsql_avc_createcon(sepgsqlGetClientContext(), tcon, tclass);
}
