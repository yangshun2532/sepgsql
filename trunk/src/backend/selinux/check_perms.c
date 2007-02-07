/*
 * src/backend/selinux/check_perms.c
 *
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"
#include "access/heapam.h"
#include "catalog/pg_aggregate.h"
#include "sepgsql.h"
#include "utils/syscache.h"
#include "utils/typcache.h"

static psid __getDatabaseContext(Datum dbid, Name dbname)
{
	Form_pg_database pgdatabase;
	HeapTuple tuple;
	psid datcon;

	tuple = SearchSysCache(DATABASEOID, dbid, 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for DATABASEOID (=%u)",
				 DatumGetObjectId(dbid));

	pgdatabase = (Form_pg_database) GETSTRUCT(tuple);
	datcon = pgdatabase->datselcon;
	if (dbname)
		strcpy(dbname->data, NameStr(pgdatabase->datname));

	ReleaseSysCache(tuple);

	return datcon;
}

static psid __getRelationContext(Datum relid, Name relname)
{
	Form_pg_class pgclass;
	HeapTuple tuple;
	psid relcon;

	tuple = SearchSysCache(RELOID, relid, 0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for RELOID (=%u)",
				 DatumGetObjectId(relid));

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
        selerror("cache lookup failed for PROCOID (=%u)",
				 DatumGetObjectId(procid));

	pgproc = (Form_pg_proc) GETSTRUCT(tuple);
	procon = pgproc->proselcon;
	if (proname)
		strcpy(proname->data, NameStr(pgproc->proname));

	ReleaseSysCache(tuple);

	return procon;
}

#define OIDS_ARRAY_MAX  (16)
static AttrNumber __getTupleContext(Oid tableoid,
									TupleDesc tdesc,
									HeapTuple tuple,
									uint16 *p_tclass,
									Oid *db_oids,
									Oid *tbl_oids,
									Oid *pro_oids)
{
	AttrNumber attno = 0;
	uint16 tclass = 0;
	int db_index = 0;
	int tbl_index=0;
	int pro_index = 0;
	bool isnull;

	switch (tableoid) {
	case AggregateRelationId: {
		/* pg_aggregate */
		pro_oids[pro_index++] =
			DatumGetObjectId(heap_getattr(tuple, Anum_pg_aggregate_aggfnoid, tdesc, &isnull));
		if (isnull)
			selerror("pg_aggregate.aggfnoid");
		tclass = SECCLASS_PROCEDURE;
		break;
	}
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
		tbl_oids[tbl_index++] =
			DatumGetObjectId(heap_getattr(tuple, Anum_pg_attribute_attrelid, tdesc, &isnull));
		if (isnull)
			selerror("pg_attribute.attrelid is NULL");

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
		if (attno < 1 || attno > tdesc->natts)
			attno = 0;
		break;
	}

	if (p_tclass)
		*p_tclass = tclass;
	if (db_oids)
		db_oids[db_index] = InvalidOid;
	if (tbl_oids)
		tbl_oids[tbl_index] = InvalidOid;
	if (pro_oids)
		pro_oids[pro_index] = InvalidOid;

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

static int ____sepgsql_tuple_perm(TupleDesc tdesc, HeapTuple tuple, uint32 perms, bool is_abort)
{
	Oid db_oids[OIDS_ARRAY_MAX];
	Oid tbl_oids[OIDS_ARRAY_MAX];
	Oid pro_oids[OIDS_ARRAY_MAX];
	uint32 attr_perms;
	AttrNumber attno;
	uint16 tclass;
	char *audit;
	int i, rc = 0;

	/* obtain tclass and additional meta info */
	attno = __getTupleContext(tuple->t_tableOid, tdesc, tuple,
							  &tclass, db_oids, tbl_oids, pro_oids);

	attr_perms = 0;
	if (perms & TUPLE__SELECT)
		attr_perms |= COMMON_DATABASE__GETATTR;
	if (perms & (TUPLE__UPDATE | TUPLE__INSERT | TUPLE__DELETE))
		attr_perms |= COMMON_DATABASE__SETATTR;

	/* check database:{getattr setattr}, if necessary */
	for (i=0; db_oids[i] != InvalidOid; i++) {
		NameData db_name;
		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(),
									 __getDatabaseContext(db_oids[i], &db_name),
									 SECCLASS_DATABASE,
									 attr_perms,
									 &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NameStr(db_name), is_abort);
	}

	/* check table:{getattr setattr}, if necessary */
	for (i=0; tbl_oids[i] != InvalidOid; i++) {
		NameData tbl_name;
		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(),
									 __getRelationContext(tbl_oids[i], &tbl_name),
									 SECCLASS_TABLE,
									 attr_perms,
									 &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NameStr(tbl_name), is_abort);
	}

	/* check procedure:{getattr setattr}, if necessary */
	for (i=0; pro_oids[i] != InvalidOid; i++) {
		NameData pro_name;
		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(),
									 __getProcedureContext(pro_oids[i], &pro_name),
									 SECCLASS_PROCEDURE,
									 attr_perms,
									 &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NameStr(pro_name), is_abort);
	}

	/* check tuple:{...}, if necessary */
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
		tuple_con = DatumGetObjectId(heap_getattr(tuple, attno, tdesc, &isnull));
		if (isnull)
			selerror("'%s' is NULL", NameStr(tdesc->attrs[attno - 1]->attname));

		rc += sepgsql_avc_permission(sepgsqlGetClientPsid(),
									 tuple_con, tclass, perms, &audit);
		__sepgsql_tuple_perm_audit(rc, audit, NULL, is_abort);
	}

	return rc;
}

static int __sepgsql_tuple_perm(Oid relid, HeapTupleHeader rec, uint32 perms, bool is_abort)
{
	HeapTupleData tuple;
	TupleDesc tdesc;
	int rc;

	/* build a temporary tuple */
	tdesc = lookup_rowtype_tupdesc(HeapTupleHeaderGetTypeId(rec),
								   HeapTupleHeaderGetTypMod(rec));
	tuple.t_len = HeapTupleHeaderGetDatumLength(rec);
	ItemPointerSetInvalid(&(tuple.t_self));
	tuple.t_tableOid = relid;
	tuple.t_data = rec;

	rc = ____sepgsql_tuple_perm(tdesc, &tuple, perms, is_abort);

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

bool
sepgsql_tuple_perm_copyto(Relation rel, HeapTuple tuple, uint32 perms)
{
	int rc = ____sepgsql_tuple_perm(RelationGetDescr(rel), tuple, perms, false);

	return (rc == 0 ? true : false);
}

HeapTuple sepgsqlExecInsert(HeapTuple newtup, MemoryContext mcontext,
							Relation rel, ProjectionInfo *retProj)
{
	Oid db_oids[OIDS_ARRAY_MAX];
	Oid tbl_oids[OIDS_ARRAY_MAX];
	Oid pro_oids[OIDS_ARRAY_MAX];
	uint16 tclass;
	uint32 perms;
	AttrNumber attno;
	char *audit;
	int i, rc;

	attno = __getTupleContext(RelationGetRelid(rel),
							  RelationGetDescr(rel),
							  newtup,
							  &tclass,
							  db_oids,
							  tbl_oids,
							  pro_oids);

	/* check database:{setattr}, if necessary */
	for (i=0; db_oids[i] != InvalidOid; i++) {
		NameData db_name;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getDatabaseContext(db_oids[i], &db_name),
									SECCLASS_DATABASE,
									DATABASE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(db_name));
	}

	/* check table:{setattr}, if necessary */
	for (i=0; tbl_oids[i] != InvalidOid; i++) {
		NameData tbl_name;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getRelationContext(tbl_oids[i], &tbl_name),
									SECCLASS_TABLE,
									TABLE__SETATTR,
									&audit);
		sepgsql_audit(rc, audit, NameStr(tbl_name));
	}

	/* check procedure:{setattr}, if necessary */
	for (i=0; pro_oids[i] != InvalidOid; i++) {
		NameData pro_name;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									__getProcedureContext(pro_oids[i], &pro_name),
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
	Oid new_db_oids[OIDS_ARRAY_MAX],  old_db_oids[OIDS_ARRAY_MAX];
	Oid new_tbl_oids[OIDS_ARRAY_MAX], old_tbl_oids[OIDS_ARRAY_MAX];
	Oid new_pro_oids[OIDS_ARRAY_MAX], old_pro_oids[OIDS_ARRAY_MAX];
    uint16 tclass, _tclass;
	AttrNumber attno, _attno;
    uint32 perms;
	char *audit;
	int i, rc;

	attno = __getTupleContext(RelationGetRelid(rel),
                              RelationGetDescr(rel),
                              newtup,
                              &tclass,
							  new_db_oids,
							  new_tbl_oids,
							  new_pro_oids);

	_attno = __getTupleContext(RelationGetRelid(rel),
							   RelationGetDescr(rel),
							   oldtup,
							   &_tclass,
							   old_db_oids,
							   old_tbl_oids,
							   old_pro_oids);
	Assert(tclass == _tclass && attno == _attno);

	for (i=0; new_db_oids[i] != InvalidOid; i++) {
		Assert(old_db_oids[i] != InvalidOid);
		if (new_db_oids[i] != old_db_oids[i]) {
			NameData db_name;
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										__getDatabaseContext(new_db_oids[i], &db_name),
										SECCLASS_DATABASE,
										DATABASE__SETATTR,
										&audit);
			sepgsql_audit(rc, audit, NameStr(db_name));
		}
	}

	for (i=0; new_tbl_oids[i] != InvalidOid; i++) {
		Assert(old_tbl_oids[i] != InvalidOid);
		if (new_tbl_oids[i] != old_tbl_oids[i]) {
			NameData tbl_name;
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										__getRelationContext(new_tbl_oids[i], &tbl_name),
										SECCLASS_TABLE,
										TABLE__SETATTR,
										&audit);
			sepgsql_audit(rc, audit, NameStr(tbl_name));
		}
	}

	for (i=0; new_pro_oids[i] != InvalidOid; i++) {
		Assert(old_pro_oids[i] != InvalidOid);
		if (new_pro_oids[i] != old_pro_oids[i]) {
			NameData pro_name;
			rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
										__getProcedureContext(new_pro_oids[i], &pro_name),
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
