/*
 * src/backend/security/sepgsqlPerms.c
 *   SE-PostgreSQL permission checking functions
 *
 * Copyright (c) 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "miscadmin.h"
#include "security/pgace.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
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
		selerror("relation %u is not exist", relid);

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
	__perms |= (perms & SEPGSQL_PERMS_USE       ? COMMON_DATABASE__GETATTR : 0);
	__perms |= (perms & SEPGSQL_PERMS_SELECT    ? COMMON_DATABASE__GETATTR : 0);
	__perms |= (perms & SEPGSQL_PERMS_UPDATE    ? COMMON_DATABASE__SETATTR : 0);
	__perms |= (perms & SEPGSQL_PERMS_INSERT    ? COMMON_DATABASE__CREATE  : 0);
	__perms |= (perms & SEPGSQL_PERMS_DELETE    ? COMMON_DATABASE__DROP    : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELFROM ? COMMON_DATABASE__RELABELFROM : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELTO ? COMMON_DATABASE__RELABELTO : 0);

	return __perms;
}

static uint32 __sepgsql_perms_to_tuple_perms(uint32 perms) {
	uint32 __perms = 0;

	//Assert((perms & ~SEPGSQL_PERMS_ALL) == 0);
	if (perms & ~SEPGSQL_PERMS_ALL)
		selbugon(1);
	__perms |= (perms & SEPGSQL_PERMS_USE       ? DB_TUPLE__USE : 0);
	__perms |= (perms & SEPGSQL_PERMS_SELECT    ? DB_TUPLE__SELECT : 0);
	__perms |= (perms & SEPGSQL_PERMS_UPDATE    ? DB_TUPLE__UPDATE : 0);
	__perms |= (perms & SEPGSQL_PERMS_INSERT    ? DB_TUPLE__INSERT : 0);
	__perms |= (perms & SEPGSQL_PERMS_DELETE    ? DB_TUPLE__DELETE : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELFROM ? DB_TUPLE__RELABELFROM : 0);
	__perms |= (perms & SEPGSQL_PERMS_RELABELTO ? DB_TUPLE__RELABELTO : 0);

	return __perms;
}

char *sepgsqlGetTupleName(Oid relid, HeapTuple tuple)
{
	char buffer[NAMEDATALEN * 2 + 32];

	switch (relid) {
	case AccessMethodRelationId:
		return NameStr(((Form_pg_am) GETSTRUCT(tuple))->amname);

	case AttributeRelationId: {
		Form_pg_attribute attrForm = (Form_pg_attribute) GETSTRUCT(tuple);
		Form_pg_class classForm;
		HeapTuple reltup;

		if (IsBootstrapProcessingMode())
			return NameStr(attrForm->attname);

		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(attrForm->attrelid),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			return NameStr(attrForm->attname);

		classForm = (Form_pg_class) GETSTRUCT(reltup);
		snprintf(buffer, sizeof(buffer), "%s.%s",
				 NameStr(classForm->relname),
				 NameStr(attrForm->attname));
		ReleaseSysCache(reltup);
		return pstrdup(buffer);
	}
	case AuthIdRelationId:
		return NameStr(((Form_pg_authid) GETSTRUCT(tuple))->rolname);

	case RelationRelationId:
		return NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname);

	case ConstraintRelationId:
		return NameStr(((Form_pg_constraint) GETSTRUCT(tuple))->conname);

	case ConversionRelationId:
		return NameStr(((Form_pg_conversion) GETSTRUCT(tuple))->conname);

	case DatabaseRelationId:
		return NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname);

	case LanguageRelationId:
		return NameStr(((Form_pg_language) GETSTRUCT(tuple))->lanname);

	case LargeObjectRelationId:
		snprintf(buffer, sizeof(buffer), "loid:%u",
				 ((Form_pg_largeobject) GETSTRUCT(tuple))->loid);
		return pstrdup(buffer);

	case ListenerRelationId:
		return NameStr(((Form_pg_listener) GETSTRUCT(tuple))->relname);

	case NamespaceRelationId:
		return NameStr(((Form_pg_namespace) GETSTRUCT(tuple))->nspname);

	case OperatorClassRelationId:
		return NameStr(((Form_pg_opclass) GETSTRUCT(tuple))->opcname);

	case OperatorRelationId:
		return NameStr(((Form_pg_operator) GETSTRUCT(tuple))->oprname);

	case PLTemplateRelationId:
		return NameStr(((Form_pg_pltemplate) GETSTRUCT(tuple))->tmplname);

	case ProcedureRelationId:
		return NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname);

	case RewriteRelationId:
		return NameStr(((Form_pg_rewrite) GETSTRUCT(tuple))->rulename);

	case TableSpaceRelationId:
		return NameStr(((Form_pg_tablespace) GETSTRUCT(tuple))->spcname);

	case TriggerRelationId:
		return NameStr(((Form_pg_trigger) GETSTRUCT(tuple))->tgname);

	case TypeRelationId:
		snprintf(buffer, sizeof(buffer), "pg_type.%s",
				 NameStr(((Form_pg_type) GETSTRUCT(tuple))->typname));
		return pstrdup(buffer);
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
	Form_pg_largeobject blobForm
		= (Form_pg_largeobject) GETSTRUCT(tuple);
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	uint32 perms = 0;

	perms |= (*p_perms & SEPGSQL_PERMS_USE    ? DB_BLOB__GETATTR : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_SELECT ? DB_BLOB__GETATTR : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_UPDATE ? DB_BLOB__SETATTR : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_READ   ? DB_BLOB__READ    : 0);
	perms |= (*p_perms & SEPGSQL_PERMS_WRITE  ? DB_BLOB__WRITE   : 0);

	if (*p_perms & SEPGSQL_PERMS_INSERT) {
		bool found = false;

		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(blobForm->loid));
		rel = heap_open(LargeObjectRelationId, AccessShareLock);
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		if (HeapTupleIsValid(systable_getnext(sd)))
            found = true;
		systable_endscan(sd);
		heap_close(rel, AccessShareLock);
		perms |= (!found ? DB_BLOB__CREATE : DB_BLOB__SETATTR | DB_BLOB__WRITE);
	}

	if (*p_perms & SEPGSQL_PERMS_DELETE) {
		HeapTuple exttup;
		bool found = false;

		ScanKeyInit(&skey,
					Anum_pg_largeobject_loid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(blobForm->loid));
		rel = heap_open(LargeObjectRelationId, AccessShareLock);
		sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
								SnapshotSelf, 1, &skey);
		while ((exttup = systable_getnext(sd))) {
			int __pageno = ((Form_pg_largeobject) GETSTRUCT(exttup))->pageno;

			if (blobForm->pageno != __pageno) {
				found = true;
				break;
			}
		}
		systable_endscan(sd);
		heap_close(rel, AccessShareLock);
		perms |= (!found ? DB_BLOB__DROP : DB_BLOB__SETATTR);
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
				if (getfilecon_raw(filename, &filecon) < 1)
					selerror("could not obtain the security context of '%s'", filename);
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
		char *audit;
		rc = sepgsql_avc_permission_noaudit(sepgsqlGetClientContext(),
											tcontext,
											tclass,
											perms,
											&audit,
											sepgsqlGetTupleName(tableoid, tuple));
		sepgsql_audit(abort ? rc : true, audit);
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

	case LargeObjectRelationId:
		tclass = SECCLASS_DB_BLOB;
		tcon = sepgsqlGetDatabaseContext();
		break;

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
