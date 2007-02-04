/*
 * src/backend/selinux/check_perms.c
 *
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"
#include "access/heapam.h"
#include "sepgsql.h"
#include "utils/syscache.h"
#include "utils/typcache.h"

static psid __getRelationContext(Datum relid, Name relname)
{
	Form_pg_class pgclass;
	HeapTuple tuple;
	psid relcon;

	tuple = SearchSysCache(RELOID, relid, 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for RELOID (=%u)", DatumGetObjectId(relid));

	pgclass = (Form_pg_class) GETSTRUCT(tuple);
	relcon = pgclass->relselcon;
	if (relname)
		strcpy(relname->data, NameStr(pgclass->relname));

	ReleaseSysCache(tuple);

	return relcon;
}

static psid __getProcedureContext(Datum procid, Name proname)
{
	Form_pg_proc pgproc;
	HeapTuple tuple;
	psid procon;

	tuple = SearchSysCache(PROCOID, procid, 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
        selerror("cache lookup failed for PROCOID (=%u)", DatumGetObjectId(procid));

	pgproc = (Form_pg_proc) GETSTRUCT(tuple);
	procon = pgproc->proselcon;
	if (proname)
		strcpy(proname->data, NameStr(pgproc->proname));

	ReleaseSysCache(tuple);

	return procon;
}

static AttrNumber __getTupleContext(Oid tableoid, TupleDesc tdesc, HeapTuple tuple,
									uint16 *p_tclass,
									Oid *p_db_oid, Oid *p_tbl_oid, Oid *p_pro_oid)
{
	AttrNumber attno = 0;
	uint16 tclass = 0;
	Oid db_oid = InvalidOid;
	Oid tbl_oid = InvalidOid;
    Oid pro_oid = InvalidOid;

	switch (tableoid) {
	case DatabaseRelationId: {
		/* pg_database */
		attno = DatabaseRelationId;
		tclass = SECCLASS_DATABASE;
		break;
	}
	case RelationRelationId: {
		/* pg_class */
		attno = Anum_pg_class_relselcon;
		tclass = SECCLASS_TABLE;
		break;
	}
	case AttributeRelationId: {
		/* pg_attribute */
		Datum relid;
		bool isnull;

		relid = heap_getattr(tuple, Anum_pg_attribute_attrelid, tdesc, &isnull);
		if (isnull)
			selerror("pg_attribute.attrelid is NULL");
		tbl_oid = DatumGetObjectId(relid);

		attno = Anum_pg_attribute_attselcon;
		tclass = SECCLASS_COLUMN;
		break;
	}
	case ProcedureRelationId: {
		/* pg_proc */
		attno = Anum_pg_proc_proselcon;
		tclass = SECCLASS_PROCEDURE;
		break;
	}
	case LargeObjectRelationId: {
		/* pg_largeobject */
		attno = Anum_pg_largeobject_selcon;
		tclass = SECCLASS_BLOB;
		break;
	}
	default:
		/* general relations */
		tclass = SECCLASS_TUPLE;
		for (attno = 1; attno <= tdesc->natts; attno++) {
			if (sepgsqlAttributeIsPsid(tdesc->attrs[attno - 1]))
				break;
		}
		break;
	}

	if (p_tclass)
		*p_tclass = tclass;
	if (p_db_oid)
		*p_db_oid = db_oid;
	if (p_tbl_oid)
		*p_tbl_oid = tbl_oid;
	if (p_pro_oid)
		*p_pro_oid = pro_oid;

	if (attno < 1 || attno > tdesc->natts)
		attno = 0;
	return attno;
}

static void __sepgsql_tuple_perm_audit(int rc, char *audit, char *objname, bool is_abort)
{
	if (audit) {
		ereport((rc && is_abort) ? ERROR : NOTICE,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 (objname
				  ? errmsg("SELinux: %s name=%s", audit, objname)
				  : errmsg("SELinux: %s", audit))));
	} else if (rc && is_abort) {
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: Transaction abort")));
	}
}

static int __sepgsql_tuple_perm(Oid relid, HeapTupleHeader rec, uint32 perms, bool is_abort)
{
	TupleDesc tdesc;
	HeapTupleData tuple;
	psid db_oid, tbl_oid, pro_oid;
	uint32 attr_perms;
	AttrNumber attno;
	uint16 tclass;
	char *audit;
	int rc = 0;

	/* build a temporary tuple */
	tdesc = lookup_rowtype_tupdesc(HeapTupleHeaderGetTypeId(rec),
								   HeapTupleHeaderGetTypMod(rec));
	tuple.t_len = HeapTupleHeaderGetDatumLength(rec);
	ItemPointerSetInvalid(&(tuple.t_self));
	tuple.t_tableOid = relid;
	tuple.t_data = rec;

	/* obtain tclass and additional meta info */
	attno = __getTupleContext(relid, tdesc, &tuple,
							  &tclass, &db_oid, &tbl_oid, &pro_oid);

	attr_perms = 0;
	if (perms & TUPLE__SELECT)
		attr_perms |= COMMON_DATABASE__GETATTR;
	if (perms & (TUPLE__UPDATE | TUPLE__INSERT | TUPLE__DELETE))
		attr_perms |= COMMON_DATABASE__SETATTR;

	if (db_oid != InvalidOid) {
		NameData db_name;
		psid db_con = __getRelationContext(db_oid, &db_name);

		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(), db_con,
									 SECCLASS_DATABASE, attr_perms, &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NameStr(db_name), is_abort);
	}

	if (tbl_oid != InvalidOid) {
		NameData tbl_name;
		psid tbl_con = __getRelationContext(tbl_oid, &tbl_name);
		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(), tbl_con,
									 SECCLASS_TABLE, attr_perms, &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NameStr(tbl_name), is_abort);
	}

	if (pro_oid != InvalidOid) {
		NameData pro_name;
		psid pro_con = __getRelationContext(pro_oid, &pro_name);
		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(), pro_con,
									 SECCLASS_TABLE, attr_perms, &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NameStr(pro_name), is_abort);
	}

	if (attno > 0 && attno <= tdesc->natts) {
		psid tuple_con;
		bool isnull;

		if (tclass != SECCLASS_TUPLE) {
			uint32 __perms = 0;

			__perms |= (perms & TUPLE__SELECT) ? COMMON_DATABASE__GETATTR : 0;
			__perms |= (perms & TUPLE__UPDATE) ? COMMON_DATABASE__SETATTR : 0;
			__perms |= (perms & TUPLE__INSERT) ? COMMON_DATABASE__CREATE  : 0;
			__perms |= (perms & TUPLE__DELETE) ? COMMON_DATABASE__DROP    : 0;

			perms = __perms;
		}
		tuple_con = DatumGetObjectId(heap_getattr(&tuple, attno, tdesc, &isnull));
		if (isnull)
			selerror("'%s' is NULL", NameStr(tdesc->attrs[attno - 1]->attname));

		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(),
									 tuple_con, tclass, perms, &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NULL, is_abort);
	}
	ReleaseTupleDesc(tdesc);

	return rc;
}

Datum
sepgsql_tuple_perm(PG_FUNCTION_ARGS)
{
    Oid relid = PG_GETARG_OID(0);
    HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(1);
    uint32 perms = PG_GETARG_UINT32(2);
    int rc;

	rc = __sepgsql_tuple_perm(relid, rec, perms, false);

	PG_RETURN_BOOL(rc == 0);
}

Datum
sepgsql_tuple_perm_abort(PG_FUNCTION_ARGS)
{
    Oid relid = PG_GETARG_OID(0);
    HeapTupleHeader rec = PG_GETARG_HEAPTUPLEHEADER(1);
    uint32 perms = PG_GETARG_UINT32(2);
    int rc;

	rc = __sepgsql_tuple_perm(relid, rec, perms, true);

	PG_RETURN_BOOL(rc == 0);
}

HeapTuple sepgsqlExecInsert(HeapTuple newtup, MemoryContext mcontext,
							Relation rel, ProjectionInfo *retProj)
{
	psid db_oid, tbl_oid, pro_oid;
	uint16 tclass;
	uint32 perms;
	AttrNumber attno;
	char *audit;
	int rc;

	attno = __getTupleContext(RelationGetRelid(rel),
							  RelationGetDescr(rel),
							  newtup,
							  &tclass,
							  &db_oid, &tbl_oid, &pro_oid);

	if (db_oid != InvalidOid) {
		NameData db_name;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getRelationContext(db_oid, &db_name),
									SECCLASS_DATABASE,
									DATABASE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(db_name));
	}

	if (tbl_oid != InvalidOid) {
		NameData tbl_name;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getRelationContext(tbl_oid, &tbl_name),
									SECCLASS_TABLE,
									TABLE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(tbl_name));
	}

	if (pro_oid != InvalidOid) {
		NameData pro_name;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getRelationContext(pro_oid, &pro_name),
									SECCLASS_PROCEDURE,
									PROCEDURE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(pro_name));
	}

	if (attno > 0 && attno <= RelationGetNumberOfAttributes(rel)) {
		psid icon, econ;
		Datum __econ;
		bool isnull;

		/* compute implicit context */
		switch (RelationGetRelid(rel)) {
		case DatabaseRelationId: {
			icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetServerPsid(),
										 SECCLASS_DATABASE);
			break;
		}
		case RelationRelationId: {
			icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetDatabasePsid(),
										 SECCLASS_TABLE);
			break;
		}
		case AttributeRelationId: {
			Datum relid;
			bool isnull;

			relid = heap_getattr(newtup, Anum_pg_attribute_attrelid,
								 RelationGetDescr(rel), &isnull);
			if (isnull)
				selerror("pg_attribute.attrelid is NULL");

			icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 __getRelationContext(relid, NULL),
										 SECCLASS_COLUMN);
			break;
		}
		case ProcedureRelationId:
			icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetDatabasePsid(),
										 SECCLASS_PROCEDURE);
			break;
		case LargeObjectRelationId:
			icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 sepgsqlGetDatabasePsid(),
										 SECCLASS_BLOB);
			break;
		default:
			icon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
										 RelationGetForm(rel)->relselcon,
										 SECCLASS_TUPLE);
			break;
		}

		/* get explicit context */
		__econ = heap_getattr(newtup, attno, RelationGetDescr(rel), &isnull);
		econ = DatumGetObjectId(__econ);

		perms = ((tclass == SECCLASS_TUPLE)
				 ? TUPLE__INSERT : COMMON_DATABASE__CREATE);
		if (isnull) {
			/* no explicit labeling */
			MemoryContext oldContext;
			Datum *values;
			bool *nulls, *repls;

			if (retProj)
				perms |= ((tclass == SECCLASS_TUPLE)
						  ? TUPLE__SELECT : COMMON_DATABASE__GETATTR);
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										icon, tclass, perms, &audit);
			sepgsql_audit(rc, audit, NULL);

			oldContext = MemoryContextSwitchTo(mcontext);
			values = palloc0(sizeof(Datum) * RelationGetNumberOfAttributes(rel));
			nulls  = palloc0(sizeof(bool)  * RelationGetNumberOfAttributes(rel));
			repls  = palloc0(sizeof(bool)  * RelationGetNumberOfAttributes(rel));

			values[attno - 1] = ObjectIdGetDatum(icon);
			nulls[attno - 1] = false;
			repls[attno - 1] = true;

			newtup = heap_modify_tuple(newtup, RelationGetDescr(rel),
									   values, nulls, repls);

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
	}
	return newtup;
}

void sepgsqlExecUpdate(HeapTuple newtup, HeapTuple oldtup,
					   Relation rel, ProjectionInfo *retProj)
{
	psid new_db_oid, new_tbl_oid, new_pro_oid;
	psid old_db_oid, old_tbl_oid, old_pro_oid;
    uint16 tclass, _tclass;
	AttrNumber attno, _attno;
    uint32 perms;
	char *audit;
	int rc;

	attno = __getTupleContext(RelationGetRelid(rel),
                              RelationGetDescr(rel),
                              newtup,
                              &tclass,
							  &new_db_oid, &new_tbl_oid, &new_pro_oid);

	_attno = __getTupleContext(RelationGetRelid(rel),
							   RelationGetDescr(rel),
							   oldtup,
							   &_tclass,
							   &old_db_oid, &old_tbl_oid, &old_pro_oid);
	Assert(tclass == _tclass && attno == _attno);

	if (old_db_oid != InvalidOid) {
		NameData db_name;
		Assert(old_db_oid != InvalidOid && new_db_oid != InvalidOid);
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getRelationContext(old_db_oid, &db_name),
									SECCLASS_DATABASE,
									DATABASE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(db_name));

		if (old_db_oid != new_db_oid) {
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										__getRelationContext(new_db_oid, &db_name),
										SECCLASS_DATABASE,
										DATABASE__SETATTR,
										&audit);
			sepgsql_audit(rc, audit, NameStr(db_name));
		}
	}

	if (old_tbl_oid != InvalidOid) {
		NameData tbl_name;
		Assert(old_tbl_oid != InvalidOid && new_tbl_oid != InvalidOid);
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getRelationContext(old_tbl_oid, &tbl_name),
									SECCLASS_TABLE,
									TABLE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(tbl_name));

		if (old_tbl_oid != new_tbl_oid) {
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										__getRelationContext(new_tbl_oid, &tbl_name),
										SECCLASS_TABLE,
										TABLE__SETATTR,
										&audit);
			sepgsql_audit(rc, audit, NameStr(tbl_name));
		}
	}

	if (old_pro_oid != InvalidOid) {
		NameData pro_name;
		Assert(old_pro_oid != InvalidOid && new_pro_oid != InvalidOid);
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getRelationContext(old_pro_oid, &pro_name),
									SECCLASS_PROCEDURE,
									PROCEDURE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(pro_name));

		if (old_pro_oid != new_pro_oid) {
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										__getRelationContext(new_pro_oid, &pro_name),
										SECCLASS_PROCEDURE,
										PROCEDURE__SETATTR,
										&audit);
			sepgsql_audit(rc, audit, NameStr(pro_name));
		}
	}

    if (attno > 0 && attno <= RelationGetNumberOfAttributes(rel)) {
		TupleDesc tdesc = RelationGetDescr(rel);
		Form_pg_attribute attr = tdesc->attrs[attno - 1];
		psid oldcon, newcon;
		bool isnull;

		perms = ((tclass == SECCLASS_TUPLE)
				 ? TUPLE__UPDATE : COMMON_DATABASE__SETATTR);
		oldcon = DatumGetObjectId(heap_getattr(oldtup, attno, tdesc, &isnull));
		if (isnull)
			selerror("%s.%s is NULL", RelationGetRelationName(rel), NameStr(attr->attname));

		newcon = DatumGetObjectId(heap_getattr(newtup, attno, tdesc, &isnull));
		if (isnull)
			selerror("%s.%s is NULL", RelationGetRelationName(rel), NameStr(attr->attname));

		if (oldcon != newcon) {
			/* client try to change security context */
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
}

void sepgsqlExecDelete(HeapTuple oldtup, Relation rel, ProjectionInfo *retProj)
{
	/* do nothing now */
}
