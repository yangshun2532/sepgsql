/*
 * src/backend/security/pgaceCommon.c
 *   Common part of PostgreSQL Access Control Extension
 * Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_security.h"
#include "executor/executor.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/parsenodes.h"
#include "security/pgace.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include <unistd.h>
#include <sys/file.h>

#ifdef SECURITY_SYSATTR_NAME
/*****************************************************************************
 *   Writable system column support
 *****************************************************************************/
void pgaceTransformSelectStmt(List *targetList) {
	ListCell *l;

	foreach (l, targetList) {
		TargetEntry *tle = lfirst(l);

		if (tle->resjunk)
			continue;
		if (!strcmp(tle->resname, SECURITY_SYSATTR_NAME))
			tle->resjunk = true;
	}
}

void pgaceTransformInsertStmt(List **p_icolumns, List **p_attrnos, List *targetList) {
	AttrNumber security_attrno = 0;
	ListCell *lc;

	foreach (lc, targetList) {
		TargetEntry *tle = (TargetEntry *) lfirst(lc);

		security_attrno++;
		if (strcmp(tle->resname, SECURITY_SYSATTR_NAME))
			continue;

		if (list_length(*p_icolumns) < list_length(targetList)) {
			List *__icolumns = NIL;
			List *__attrnos = NIL;
			ListCell *l1, *l2;
			int index = 0;

			forboth(l1, *p_icolumns, l2, *p_attrnos) {
				if (++index == security_attrno) {
					ResTarget *col = makeNode(ResTarget);
					col->name = pstrdup(SECURITY_SYSATTR_NAME);
					col->indirection = NIL;
					col->val = NULL;
					col->location = -1;

					__icolumns = lappend(__icolumns, col);
					__attrnos = lappend_int(__attrnos, SecurityAttributeNumber);
				}
				if (lfirst_int(l2) == SecurityAttributeNumber)
					return;
				__icolumns = lappend(__icolumns, lfirst(l1));
				__attrnos = lappend_int(__attrnos, lfirst_int(l2));
			}
			*p_icolumns = __icolumns;
			*p_attrnos = __attrnos;
		}
		break;
	}
}

void pgaceFetchSecurityLabel(JunkFilter *junkfilter, TupleTableSlot *slot, Oid *tts_security) {
	Datum datum;
	bool isNull;

	if (ExecGetJunkAttribute(junkfilter,
							 slot,
							 SECURITY_SYSATTR_NAME,
							 &datum,
							 &isNull) && !isNull)
		*tts_security = DatumGetObjectId(datum);
}
#endif /* SECURITY_SYSATTR_NAME */

/*****************************************************************************
 *   Extended SQL statements support
 *****************************************************************************/

/* CREATE TABLE with explicit CONTEXT */
List *pgaceBuildAttrListForRelation(CreateStmt *stmt) {
	List *result = NIL;
	ListCell *l;
	DefElem *defel, *newel;
	Oid t_security;

	if (stmt->pgace_item) {
		defel = (DefElem *) stmt->pgace_item;
		Assert(IsA(defel, DefElem));
		
		t_security = pgaceParseSecurityLabel(defel);
		newel = makeDefElem(NULL, (Node *) makeInteger(t_security));

		result = lappend(result, newel);
	}

	foreach (l, stmt->tableElts) {
		ColumnDef *cdef = (ColumnDef *) lfirst(l);
		defel = (DefElem *) cdef->pgace_item;

		if (defel) {
			Assert(IsA(defel, DefElem));
			t_security = pgaceParseSecurityLabel(defel);
			newel = makeDefElem(pstrdup(cdef->colname),
								(Node *) makeInteger(t_security));

			result = lappend(result, newel);
		}
	}

	return result;
}

void pgaceCreateRelationCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list) {
	ListCell *l;

	foreach (l, pgace_attr_list) {
		DefElem *defel = (DefElem *) lfirst(l);

		if (!defel->defname) {
			Oid t_security = intVal(defel->arg);

			HeapTupleSetSecurity(tuple, t_security);
			break;
		}
	}
}

void pgaceCreateAttributeCommon(Relation rel, HeapTuple tuple, List *pgace_attr_list) {
	Form_pg_attribute attr = (Form_pg_attribute) GETSTRUCT(tuple);
	ListCell *l;

	foreach (l, pgace_attr_list) {
		DefElem *defel = lfirst(l);

		if (!defel->defname)
			continue;	/* for table */
		if (!strcmp(defel->defname, NameStr(attr->attname))) {
			Oid t_security = intVal(defel->arg);

			HeapTupleSetSecurity(tuple, t_security);
			break;
		}
	}
}

/* ALTER <tblname> [ALTER <colname>] CONTEXT = 'xxx' statement */
static void alterRelationCommon(Relation rel, DefElem *defel) {
	Relation pg_class;
	HeapTuple tuple;
	Oid t_security;

	pg_class = heap_open(RelationRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy(RELOID,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("relation '%s' does not exist",
						RelationGetRelationName(rel))));

	t_security = pgaceParseSecurityLabel(defel);
	HeapTupleSetSecurity(tuple, t_security);

	simple_heap_update(pg_class, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_class, tuple);

	heap_freetuple(tuple);
	heap_close(pg_class, RowExclusiveLock);
}

static void alterAttributeCommon(Relation rel, char *colName, DefElem *defel) {
	Relation pg_attr;
	HeapTuple tuple;
	Oid t_security;

	pg_attr = heap_open(AttributeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopyAttName(RelationGetRelid(rel), colName);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("column \"%s\" of relation \"%s\" does not exist",
						colName, RelationGetRelationName(rel))));

	t_security = pgaceParseSecurityLabel(defel);
	HeapTupleSetSecurity(tuple, t_security);

	simple_heap_update(pg_attr, &tuple->t_self, tuple);
	CatalogUpdateIndexes(pg_attr, tuple);

	heap_freetuple(tuple);
	heap_close(pg_attr, RowExclusiveLock);
}

void pgaceAlterRelationCommon(Relation rel, AlterTableCmd *cmd) {
	DefElem *defel = (DefElem *) cmd->def;

	Assert(IsA(defel, DefElem));

	if (!pgaceNodeIsSecurityLabel(defel))
		elog(ERROR, "unrecognized security attribute");

	if (!cmd->name) {
		alterRelationCommon(rel, defel);
	} else {
		alterAttributeCommon(rel, cmd->name, defel);
	}
}

static void pgacePutSecurityLabel(HeapTuple tuple, DefElem *defel) {
	Oid t_security;

	if (!defel)
		return;

	Assert(IsA(defel, DefElem) && IsA(defel->arg, String));

	t_security = pgaceParseSecurityLabel(defel);
	HeapTupleSetSecurity(tuple, t_security);
}

void pgaceCreateDatabaseCommon(HeapTuple tuple, DefElem *defel) {
	pgacePutSecurityLabel(tuple, defel);
}

void pgaceAlterDatabaseCommon(HeapTuple tuple, DefElem *defel) {
	pgacePutSecurityLabel(tuple, defel);
}

void pgaceCreateFunctionCommon(HeapTuple tuple, DefElem *defel) {
	pgacePutSecurityLabel(tuple, defel);
}

void pgaceAlterFunctionCommon(HeapTuple tuple, DefElem *defel) {
	pgacePutSecurityLabel(tuple, defel);
}

/*****************************************************************************
 *   security_label type input/output handler
 *****************************************************************************/
static Oid early_security_label_to_sid(char *seclabel);
static char *early_sid_to_security_label(Oid sid);
#define EARLY_PG_SECURITY  "global/pg_security.bootstrap"

static bool pg_security_is_available() {
	/* -1 : early mode, 0: now in transfer, 1: available */
	static int pg_security_state = -1;
	char fname[MAXPGPATH];
	FILE *filp;

	if (pg_security_state > 0)
		return true;
	if (IsBootstrapProcessingMode() || pg_security_state == 0)
		return false;
	/*
	 * if initial setting up was not done, the cache file is remaining.
	 * so we have to insert its contains into pg_selinux.
	 * we can make decision of whether it already done, or not, by looking
	 * the existance of 'EARLY_PG_SECURITY'.
	 */
	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SECURITY);
	filp = fopen(fname, "a+");
	if (filp) {
		Relation rel;
		CatalogIndexState ind;
		HeapTuple tuple;
		char buffer[1024];
		Oid secoid, metaoid;
		Datum value;
		char  isnull;

		pg_security_state = 0;

		PG_TRY();
		{
			rel = heap_open(SecurityRelationId, RowExclusiveLock);
			ind = CatalogOpenIndexes(rel);
			while (fscanf(filp, "%u %s", &secoid, buffer) == 2) {
				metaoid = early_security_label_to_sid(pgaceSecurityLabelOfLabel(buffer));

				value = DirectFunctionCall1(textin, CStringGetDatum(buffer));
				isnull = ' ';
				tuple = heap_formtuple(RelationGetDescr(rel), &value, &isnull);

				HeapTupleSetOid(tuple, secoid);
				HeapTupleSetSecurity(tuple, metaoid);

				simple_heap_insert(rel, tuple);
				CatalogIndexInsert(ind, tuple);

				heap_freetuple(tuple);
			}
			CatalogCloseIndexes(ind);
			heap_close(rel, RowExclusiveLock);

			CommandCounterIncrement();
			CatalogCacheFlushRelation(SecurityRelationId);
		}
		PG_CATCH();
		{
			fclose(filp);
			pg_security_state = -1;
			PG_RE_THROW();
		}
		PG_END_TRY();
		fclose(filp);
		unlink(fname);
	}
	pg_security_state = 1;

	return true;
}

static Oid early_security_label_to_sid(char *seclabel)
{
	char fname[MAXPGPATH], buffer[1024];
	Oid sid, minsid = SecurityRelationId;
	FILE *filp;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SECURITY);
	filp = fopen(fname, "a+b");
	if (!filp)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("could not open '%s'", fname)));
	flock(fileno(filp), LOCK_EX);
    while (fscanf(filp, "%u %s", &sid, buffer) == 2) {
		if (!strcmp(seclabel, buffer)) {
			fclose(filp);
			return sid;
		}
		if (sid < minsid)
			minsid = sid;
	}
	if (!pgaceSecurityLabelIsValid(seclabel))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("'%s' is not a valid security label", seclabel)));

	sid = minsid - 1;
	fprintf(filp, "%u %s\n", sid, seclabel);
	fclose(filp);

	return sid;
}

static char *early_sid_to_security_label(Oid sid)
{
	char fname[MAXPGPATH], buffer[1024], *seclabel;
	FILE *filp;
	Oid __sid;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SECURITY);
    filp = fopen(fname, "rb");
	if (!filp)
		goto not_found;

	flock(fileno(filp), LOCK_SH);
    while (fscanf(filp, "%u %s", &__sid, buffer) == 2) {
        if (sid == __sid) {
            fclose(filp);
            return pstrdup(buffer);
        }
    }
    fclose(filp);

not_found:
	seclabel = pgaceSecurityLabelNotFound(sid);
	ereport((seclabel ? DEBUG1 : ERROR),
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("No text representation for sid = %u", sid)));
	return seclabel;
}

static Oid get_security_label_oid(Relation rel, CatalogIndexState ind, char *new_label)
{
	/* rel has to be opened with RowExclusiveLock */
	char *meta_label_str = pgaceSecurityLabelOfLabel(new_label);
	Datum meta_label;
	HeapTuple tuple;
	Oid label_oid;

	if (!pgaceSecurityLabelIsValid(meta_label_str))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("'%s' is not a valid security label", meta_label_str)));

	meta_label = DirectFunctionCall1(textin, CStringGetDatum(meta_label_str));
	tuple = SearchSysCache(SECURITYLABEL, meta_label, 0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		label_oid = HeapTupleGetSecurity(tuple);
		ReleaseSysCache(tuple);
	} else {
		/* Insert a new tuple into pg_security */
		Oid __label_oid;
		Datum values[1] = {meta_label};
		char nulls[1] = {' '};

		tuple = heap_formtuple(RelationGetDescr(rel), values, nulls);
		__label_oid = GetNewOid(rel);
		HeapTupleSetOid(tuple, __label_oid);
		HeapTupleSetSecurity(tuple, __label_oid);

		label_oid = simple_heap_insert(rel, tuple);
		Assert(label_oid == __label_oid);

		CatalogIndexInsert(ind, tuple);
		CommandCounterIncrement();
	}
	return label_oid;
}

static Oid security_label_to_sid(char *sec_label_str)
{
	HeapTuple tuple;
	Datum sec_label;
	Oid label_oid;

	if (!pg_security_is_available())
		return early_security_label_to_sid(sec_label_str);

	sec_label = DirectFunctionCall1(textin, CStringGetDatum(sec_label_str));
	tuple = SearchSysCache(SECURITYLABEL, sec_label, 0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		label_oid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
	} else {
		/* INSERT a new security label into pg_security */
		Relation rel;
		CatalogIndexState ind;
		Datum values[1] = { sec_label };
		char nulls[1] = {' '};

		if (!pgaceSecurityLabelIsValid(sec_label_str))
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("'%s' is not a valid security label", sec_label_str)));

		rel = heap_open(SecurityRelationId, RowExclusiveLock);
		ind = CatalogOpenIndexes(rel);

		tuple = heap_formtuple(RelationGetDescr(rel), values, nulls);
		HeapTupleSetSecurity(tuple, get_security_label_oid(rel, ind, sec_label_str));

		label_oid = simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		CatalogCloseIndexes(ind);
		heap_close(rel, RowExclusiveLock);

		CommandCounterIncrement();
		CatalogCacheFlushRelation(SecurityRelationId);
	}
	return label_oid;
}

static char *sid_to_security_label(Oid sid)
{
	HeapTuple tuple;
	Relation rel;
	Datum tcon;
	char *seclabel;
	bool isnull;

	if (!pg_security_is_available())
		return early_sid_to_security_label(sid);

	rel = heap_open(SecurityRelationId, AccessShareLock);

	tuple = SearchSysCache(SECURITYOID, ObjectIdGetDatum(sid), 0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		tcon = heap_getattr(tuple, Anum_pg_security_seclabel,
							RelationGetDescr(rel), &isnull);
		tcon = DirectFunctionCall1(textout, PointerGetDatum(tcon));
		seclabel = pstrdup(DatumGetCString(tcon));

		ReleaseSysCache(tuple);
	} else {
		seclabel = pgaceSecurityLabelNotFound(sid);
		ereport((seclabel ? DEBUG1 : ERROR),
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("No text representation for sid = %u", sid)));
	}
	heap_close(rel, AccessShareLock);

	return seclabel;
}

/* security_label_in -- security_label input function */
Datum
security_label_in(PG_FUNCTION_ARGS)
{
	char *label = PG_GETARG_CSTRING(0);
	Oid sid;

	label = pgaceSecurityLabelIn(label);
	sid = security_label_to_sid(label);

	PG_RETURN_OID(sid);
}

/* security_label_out -- security_label output function */
Datum
security_label_out(PG_FUNCTION_ARGS)
{
	Oid sid = PG_GETARG_OID(0);
	char *label;

	label = sid_to_security_label(sid);
	label = pgaceSecurityLabelOut(label);

	PG_RETURN_CSTRING(label);
}

/* security_label_raw_in -- security_label input function in raw format */
Datum
security_label_raw_in(PG_FUNCTION_ARGS)
{
	char *label = PG_GETARG_CSTRING(0);

	PG_RETURN_OID(security_label_to_sid(label));
}

/* security_label_raw_out -- security_label output function in raw format */
Datum
security_label_raw_out(PG_FUNCTION_ARGS)
{
	Oid sid = PG_GETARG_OID(0);

	PG_RETURN_CSTRING(sid_to_security_label(sid));
}

/* text_to_security_label -- security_label cast function */
Datum
text_to_security_label(PG_FUNCTION_ARGS)
{
	text *t = PG_GETARG_TEXT_P(0);
	char *seclabel;
	int len;
	Datum sid;

	len = VARSIZE(t) - VARHDRSZ;
	seclabel = palloc0(len + 1);
	memcpy(seclabel, VARDATA(t), len);
	sid = DirectFunctionCall1(security_label_in,
							  CStringGetDatum(seclabel));
	pfree(seclabel);
	PG_RETURN_DATUM(sid);
}

/* security_label_to_text -- security_label cast function */
Datum
security_label_to_text(PG_FUNCTION_ARGS)
{
	Oid sid = PG_GETARG_OID(0);
	char *context;
	text *result;

	context = DatumGetCString(DirectFunctionCall1(security_label_out,
												  ObjectIdGetDatum(sid)));
	result = palloc(VARHDRSZ + strlen(context));
	VARATT_SIZEP(result) = VARHDRSZ + strlen(context);
	memcpy(VARDATA(result), context, strlen(context));

	PG_RETURN_TEXT_P(result);
}

/*****************************************************************************
 *	 Set/Get security attribute of Large Object
 *****************************************************************************/
Datum
lo_get_security(PG_FUNCTION_ARGS)
{
	Oid loid = PG_GETARG_OID(0);
	Oid lo_security = InvalidOid;
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple;
	bool found = false;

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, AccessShareLock);

	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);

	while ((tuple = systable_getnext(sd)) != NULL) {
		lo_security = pgaceLargeObjectGetSecurity(tuple);
		found = true;
		break;
	}
	systable_endscan(sd);

	heap_close(rel, AccessShareLock);

	if (!found)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));

	PG_RETURN_OID(lo_security);
}

Datum
lo_set_security(PG_FUNCTION_ARGS)
{
	Oid loid = PG_GETARG_OID(0);
	Oid lo_security = PG_GETARG_OID(1);
	Relation rel;
	ScanKeyData skey;
	SysScanDesc sd;
	HeapTuple tuple, newtup;
	CatalogIndexState indstate;
	bool found = false;

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loid));

	rel = heap_open(LargeObjectRelationId, RowExclusiveLock);

	indstate = CatalogOpenIndexes(rel);

	sd = systable_beginscan(rel, LargeObjectLOidPNIndexId, true,
							SnapshotNow, 1, &skey);

	while ((tuple = systable_getnext(sd)) != NULL) {
		newtup = heap_copytuple(tuple);
		pgaceLargeObjectSetSecurity(newtup, lo_security, !found);
		simple_heap_update(rel, &newtup->t_self, newtup);
		CatalogUpdateIndexes(rel, newtup);
		found = true;
	}
	systable_endscan(sd);
	CatalogCloseIndexes(indstate);
	heap_close(rel, RowExclusiveLock);

	CommandCounterIncrement();

	if (!found)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("large object %u does not exist", loid)));

	PG_RETURN_BOOL(true);
}

#ifndef HAVE_SELINUX
/* dummy definitions for SE-PostgreSQL */
Datum sepgsql_getcon(PG_FUNCTION_ARGS);
Datum sepgsql_tuple_perms(PG_FUNCTION_ARGS);
Datum sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS);

Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
			 errmsg("SE-PostgreSQL is not configured")));
	PG_RETURN_OID(InvalidOid);
}

Datum
sepgsql_tuple_perms(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
			 errmsg("SE-PostgreSQL is not configured")));
	PG_RETURN_BOOL(false);
}

Datum
sepgsql_tuple_perms_abort(PG_FUNCTION_ARGS)
{
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_FUNCTION_DEFINITION),
			 errmsg("SE-PostgreSQL is not configured")));
	PG_RETURN_BOOL(false);
}
#endif
