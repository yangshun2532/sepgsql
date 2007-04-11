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
#include "catalog/pg_largeobject.h"
#include "catalog/pg_security.h"
#include "executor/executor.h"
#include "miscadmin.h"
#include "security/pgace.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/syscache.h"
#include <unistd.h>
#include <sys/file.h>

/*
 * support for writable system column
 */
#ifdef SECURITY_SYSATTR_NAME
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

#define EARLY_PG_SECURITY  "global/pg_security.bootstrap"

static bool pg_security_is_available() {
	static bool __pg_security_is_available = false;
	char fname[MAXPGPATH];
	FILE *filp;

	if (__pg_security_is_available)
		return true;
	if (IsBootstrapProcessingMode())
		return false;
	/*
	 * if initial setting up was not done, the cache file is remaining.
	 * so we have to insert its contains into pg_selinux.
	 * we can make decision of whether it already done, or not, by looking
	 * the existance of 'EARLY_PG_SECURITY'.
	 */
	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SECURITY);
	filp = fopen(fname, "rb");
	if (filp) {
		Relation rel;
		CatalogIndexState ind;
		HeapTuple tuple;
		Oid tupcon = pgaceSecurityLabelOfLabel(true);

		PG_TRY();
		{
			char buffer[1024];
			Oid sid;
			Datum value;
			char isnull;

			rel = heap_open(SecurityRelationId, RowExclusiveLock);
			ind = CatalogOpenIndexes(rel);
			while (fscanf(filp, "%u %s", &sid, buffer) == 2) {
				value = DirectFunctionCall1(textin, CStringGetDatum(buffer));
				isnull = ' ';
				tuple = heap_formtuple(RelationGetDescr(rel), &value, &isnull);
				HeapTupleSetOid(tuple, sid);
				HeapTupleSetSecurity(tuple, tupcon);

				heap_insert(rel, tuple, GetCurrentCommandId(), true, true);
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
			PG_RE_THROW();
		}
		PG_END_TRY();
		fclose(filp);
		unlink(fname);
	}
	__pg_security_is_available = true;

	return true;
}

Oid early_security_label_to_sid(char *context)
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
		if (!strcmp(context, buffer)) {
			fclose(filp);
			return sid;
		}
		if (sid < minsid)
			minsid = sid;
	}
	if (!pgaceSecurityLabelIsValid(context))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("'%s' is not a valid context", context)));

	sid = minsid - 1;
	fprintf(filp, "%u %s\n", sid, context);
	fclose(filp);

	return sid;
}

char *early_sid_to_security_label(Oid sid)
{
	char fname[MAXPGPATH], buffer[1024];
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
	ereport(ERROR,
			(errcode(ERRCODE_INTERNAL_ERROR),
			 errmsg("No text representation for sid = %u", sid)));
	return NULL; /* for compiler kindness */
}

Oid security_label_to_sid(char *context)
{
	HeapTuple tuple;
	Datum tcon;
	Oid sid;

	if (!pg_security_is_available())
		return early_security_label_to_sid(context);

	tcon = DirectFunctionCall1(textin, CStringGetDatum(context));
	tuple = SearchSysCache(SECURITYLABEL, tcon, 0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		sid = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
	} else {
		/* INSERT a new security label into pg_security */
		Relation rel;
		CatalogIndexState ind;
		Oid ncon;
		Datum values[1] = { tcon };
		char nulls[1] = {' '};

		if (!pgaceSecurityLabelIsValid(context))
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("'%s' is not a valid context", context)));

		ncon = pgaceSecurityLabelOfLabel(false);
		rel = heap_open(SecurityRelationId, RowExclusiveLock);
		ind = CatalogOpenIndexes(rel);

		tuple = heap_formtuple(RelationGetDescr(rel), values, nulls);
		HeapTupleSetSecurity(tuple, ncon);
		sid = simple_heap_insert(rel, tuple);
		CatalogIndexInsert(ind, tuple);

		CatalogCloseIndexes(ind);
		heap_close(rel, RowExclusiveLock);

		CommandCounterIncrement();
		CatalogCacheFlushRelation(SecurityRelationId);
	}
	return sid;
}

char *sid_to_security_label(Oid sid)
{
	HeapTuple tuple;
	Relation rel;
	Datum tcon;
	char *context;
	bool isnull;

	if (!pg_security_is_available())
		return early_sid_to_security_label(sid);

	rel = heap_open(SecurityRelationId, AccessShareLock);

	tuple = SearchSysCache(SECURITYOID, ObjectIdGetDatum(sid), 0, 0, 0);
	if (!HeapTupleIsValid(tuple)) {
		char *bugon = NULL;
		ereport(NOTICE,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("No text representation for sid = %u", sid)));
		bugon[0] = 'a';
	}

	tcon = heap_getattr(tuple, Anum_pg_security_seclabel,
						RelationGetDescr(rel), &isnull);
	context = DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(tcon)));
	ReleaseSysCache(tuple);

	heap_close(rel, AccessShareLock);

	return context;
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
	text *tmp = PG_GETARG_TEXT_P(0);
	char *context;
	Datum sid;

	context = VARDATA(tmp);
	sid = DirectFunctionCall1(security_label_in,
							  CStringGetDatum(context));
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
