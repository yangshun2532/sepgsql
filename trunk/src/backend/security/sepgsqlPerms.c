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
			*p_tclass = SECCLASS_TUPLE;
			return;
		}
		break;
	}
	*p_tclass = SECCLASS_COLUMN;
	*p_perms = __tuple_perms_to_common_perms(*p_perms);
	if (HeapTupleIsValid(oldtup)) {
		Form_pg_attribute oldForm = (Form_pg_attribute) GETSTRUCT(oldtup);

		if (oldForm->attisdropped != true && attrForm->attisdropped == true)
			*p_perms |= COLUMN__DROP;
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

	perms |= (*p_perms & TUPLE__SELECT ? BLOB__GETATTR : 0);
	perms |= (*p_perms & TUPLE__UPDATE ? BLOB__SETATTR : 0);
	perms |= (*p_perms & BLOB__READ    ? BLOB__READ    : 0);
	perms |= (*p_perms & BLOB__WRITE   ? BLOB__WRITE   : 0);

	if (*p_perms & TUPLE__INSERT) {
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
		perms |= (!found ? BLOB__CREATE : BLOB__SETATTR);
	}

	if (*p_perms & TUPLE__DELETE) {
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
		perms |= (!found ? BLOB__DROP : BLOB__SETATTR);
	}
	*p_tclass = SECCLASS_BLOB;
	*p_perms = perms;
}

static void __check_pg_proc(HeapTuple tuple, HeapTuple oldtup,
							uint32 *p_perms, uint16 *p_tclass)
{
	uint32 perms = __tuple_perms_to_common_perms(*p_perms);
	Form_pg_proc procForm = (Form_pg_proc) GETSTRUCT(tuple);

	if (procForm->prolang == ClanguageId) {
		Datum oldbin, newbin;
		bool isnull, verify = false;

		newbin = SysCacheGetAttr(PROCOID, tuple,
								 Anum_pg_proc_probin, &isnull);
		if (!isnull) {
			if (perms & PROCEDURE__CREATE) {
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
									   SECCLASS_DATABASE,
									   DATABASE__INSTALL_MODULE,
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
									   SECCLASS_DATABASE,
									   DATABASE__INSTALL_MODULE,
									   filename);
			}
		}
	}
	*p_perms = perms;
	*p_tclass = SECCLASS_PROCEDURE;
}

static void __check_pg_relation(HeapTuple tuple, HeapTuple oldtup,
								uint32 *p_perms, uint16 *p_tclass)
{
	Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
	if (classForm->relkind == RELKIND_RELATION) {
		*p_tclass = SECCLASS_TABLE;
		*p_perms = __tuple_perms_to_common_perms(*p_perms);
	} else {
		*p_tclass = SECCLASS_TUPLE;
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
		perms = __tuple_perms_to_common_perms(perms);
		tclass = SECCLASS_DATABASE;
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
		tclass = SECCLASS_TUPLE;
		break;
	}

	if (perms) {
		char *audit;
		char *object_name = __tuple_system_object_name(tableoid, tuple);
		rc = sepgsql_avc_permission_noaudit(sepgsqlGetClientContext(),
											tcontext,
											tclass,
											perms,
											&audit,
											object_name);
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
		tclass = SECCLASS_DATABASE;
		tcon = sepgsqlGetServerContext();
		break;

	case RelationRelationId: {		/* pg_class */
		Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
		if (classForm->relkind == RELKIND_RELATION) {
			tclass = SECCLASS_TABLE;
			tcon = sepgsqlGetDatabaseContext();
			break;
		}
		tcon = __lookupRelationForm(RelationRelationId, NULL);
		tclass = SECCLASS_TUPLE;
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
										 SECCLASS_TABLE);
			tclass = SECCLASS_COLUMN;
			break;
		}
		tcon = __lookupRelationForm(attrForm->attrelid, &classForm);
		tclass = (classForm.relkind == RELKIND_RELATION
				  ? SECCLASS_COLUMN
				  : SECCLASS_TUPLE);
		break;
	}
	case ProcedureRelationId:
		tclass = SECCLASS_PROCEDURE;
		tcon = sepgsqlGetDatabaseContext();
		break;

	case LargeObjectRelationId:
		tclass = SECCLASS_BLOB;
		tcon = sepgsqlGetDatabaseContext();
		break;

	case TypeRelationId:		/* pg_type */
		if (IsBootstrapProcessingMode()) {
			/* special case in early phase */
			tcon = sepgsql_avc_createcon(sepgsqlGetClientContext(),
										 sepgsqlGetDatabaseContext(),
										 SECCLASS_TABLE);
			tclass = SECCLASS_TUPLE;
			break;
		}
	default:
		tclass = SECCLASS_TUPLE;
		tcon = __lookupRelationForm(RelationGetRelid(rel), NULL);
		break;
	}
	return sepgsql_avc_createcon(sepgsqlGetClientContext(), tcon, tclass);
}
