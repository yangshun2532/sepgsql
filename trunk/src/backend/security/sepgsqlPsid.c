/*
 * src/backend/security/sepgsqlPsid.c
 *   SE-PostgreSQL : psid <--> string expression translation.
 *
 * Conpyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/indexing.h"
#include "catalog/pg_selinux.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <sys/file.h>
#include <unistd.h>

#define EARLY_PG_SELINUX  "global/pg_selinux.bootstrap"

static psid early_context_to_psid(char *context)
{
	char fname[MAXPGPATH], buffer[1024];
	psid sid, minsid = SelinuxRelationId;
	FILE *filp;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SELINUX);
	filp = fopen(fname, "a+b");
	if (!filp)
		selerror("could not open '%s'", fname);
	flock(fileno(filp), LOCK_EX);
	while (fscanf(filp, "%u %s", &sid, buffer) == 2) {
		if (!strcmp(context, buffer)) {
			fclose(filp);
			return sid;
		}
		if (sid < minsid)
			minsid = sid;
	}
	if (!sepgsql_check_context(context))
		selerror("'%s' is not valid security context", ((char *)2UL));

	sid = minsid - 1;
	fprintf(filp, "%u %s\n", sid, context);
	fclose(filp);

	return sid;
}

static char *early_psid_to_context(psid selcon)
{
	char fname[MAXPGPATH], buffer[1024];
	FILE *filp;
	psid cursid;

	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SELINUX);
	filp = fopen(fname, "rb");
	if (!filp)
		goto not_found;
	flock(fileno(filp), LOCK_SH);
	while (fscanf(filp, "%u %s", &cursid, buffer) == 2) {
		if (cursid == selcon) {
			fclose(filp);
			return pstrdup(buffer);
		}
	}
	fclose(filp);

not_found:
	selerror("No string expression for psid=%u", selcon);
	return NULL;
}

static psid __get_pg_selinux_tuple_context(bool early_mode)
{
	HeapTuple tuple;
	security_context_t scon, tcon, ncon;
	psid tupcon;
	int rc;

	/* obtain pg_selinux's implicit context */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SelinuxRelationId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		selerror("cache lookup failed for relation = %u", SelinuxRelationId);
	if (early_mode) {
		tcon = early_psid_to_context(HeapTupleGetSecurity(tuple));
	} else {
		tcon = sepgsql_psid_to_context(HeapTupleGetSecurity(tuple));
	}

	/* obtain server's context */
	rc = getcon_raw(&scon);
	if (rc)
		selerror("could not obtain server's context");

	/* compute pg_selinux tuple context */
	rc = security_compute_create_raw(scon, tcon, SECCLASS_TUPLE, &ncon);
	pfree(tcon);
	freecon(scon);
	if (rc)
		selerror("could not compute a newly created security context");

	/* obtain tuple's context */
	PG_TRY();
	{
		if (early_mode) {
			tupcon = early_context_to_psid(ncon);
		} else {
			tupcon = sepgsql_context_to_psid(ncon);
		}
	}
	PG_CATCH();
	{
		freecon(ncon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(ncon);

	return tupcon;
}

static bool pg_selinux_is_available()
{
	static bool __pg_selinux_is_available = false;
	char fname[MAXPGPATH];
	FILE *filp;

	if (__pg_selinux_is_available)
		return true;
	if (IsBootstrapProcessingMode())
		return false;

	/*
	 * if initial setting up was not done, the cache file is remaining.
	 * so we have to insert its contains into pg_selinux.
	 * we can make decision of whether it already done, or not, by looking
	 * the existance of 'EARLY_PG_SELINUX'.
	 */
	snprintf(fname, sizeof(fname), "%s/%s", DataDir, EARLY_PG_SELINUX);
	filp = fopen(fname, "rb");
	if (filp) {
		Relation rel;
		CatalogIndexState index;
		HeapTuple tuple;
		psid tupcon = __get_pg_selinux_tuple_context(true);

		PG_TRY();
		{
			char buffer[1024];
			psid selcon;
			Datum value;
			char isnull;

			rel = heap_open(SelinuxRelationId, RowExclusiveLock);
			index = CatalogOpenIndexes(rel);
			while (fscanf(filp, "%u %s", &selcon, buffer) == 2) {
				value = DirectFunctionCall1(textin, CStringGetDatum(buffer));
				isnull = ' ';
				tuple = heap_formtuple(RelationGetDescr(rel), &value, &isnull);
				HeapTupleSetOid(tuple, selcon);
				HeapTupleSetSecurity(tuple, tupcon);

				heap_insert(rel, tuple, GetCurrentCommandId(), true, true);
				CatalogIndexInsert(index, tuple);

				heap_freetuple(tuple);
			}
			CatalogCloseIndexes(index);
			heap_close(rel, NoLock);

			CommandCounterIncrement();
			CatalogCacheFlushRelation(SelinuxRelationId);
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
	__pg_selinux_is_available = true;

	return true;
}

psid sepgsql_context_to_psid(char *context)
{
	HeapTuple tuple;
	Datum tcon;
	psid selcon, tupcon;

	if (!pg_selinux_is_available())
		return early_context_to_psid(context);

	tcon = DirectFunctionCall1(textin, CStringGetDatum(context));
	tuple = SearchSysCache(SELINUXCONTEXT, tcon, 0, 0, 0);
	if (HeapTupleIsValid(tuple)) {
		selcon = HeapTupleGetOid(tuple);
		ReleaseSysCache(tuple);
	} else {
		/* insert a new security context into pg_selinux and index */
		Relation pgselinux;
		CatalogIndexState indstate;
		Datum values[1] = { tcon };
		char nulls[1] = {' '};

		if (sepgsql_check_context(context) != true)
			selerror("'%s' is not valid security context", context);

		tupcon = __get_pg_selinux_tuple_context(false);

		pgselinux = heap_open(SelinuxRelationId, RowExclusiveLock);
		indstate = CatalogOpenIndexes(pgselinux);

		tuple = heap_formtuple(RelationGetDescr(pgselinux), values, nulls);
		HeapTupleSetSecurity(tuple, tupcon);
		selcon = simple_heap_insert(pgselinux, tuple);
		CatalogIndexInsert(indstate, tuple);

		CatalogCloseIndexes(indstate);
		heap_close(pgselinux, NoLock);

		CommandCounterIncrement();
		CatalogCacheFlushRelation(SelinuxRelationId);
	}
	return selcon;
}

char *sepgsql_psid_to_context(psid selcon)
{
	Relation pgselinux;
	HeapTuple tuple;
	Datum tcon;
	char *context;
	bool isnull;

	if (!pg_selinux_is_available())
		return early_psid_to_context(selcon);

	pgselinux = heap_open(SelinuxRelationId, AccessShareLock);

	tuple = SearchSysCache(SELINUXOID, ObjectIdGetDatum(selcon), 0, 0, 0);
	if (!HeapTupleIsValid(tuple)) {
		selnotice("No string expression for psid=%u", selcon);
		selbugon(true);
		selerror("No string expression for psid=%u", selcon);
	}

	tcon = heap_getattr(tuple, Anum_pg_selinux_selcontext,
						RelationGetDescr(pgselinux), &isnull);
	context = DatumGetCString(DirectFunctionCall1(textout, PointerGetDatum(tcon)));

	ReleaseSysCache(tuple);
	heap_close(pgselinux, NoLock);

	return context;
}

bool sepgsql_check_context(char *context)
{
	return (security_check_context_raw(context) == 0 ? true : false);
}

/* translate a raw formatted context into mcstrans'ed one */
static char *__psid_raw_to_trans_context(char *raw_context)
{
	security_context_t context;
	char *result;

	if (selinux_raw_to_trans_context(raw_context, &context))
		selerror("could not translate MLS label");
	PG_TRY();
	{
		result = pstrdup(context);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);

	return result;
}

/* translate a mcstrans'ed context into raw formatted one */
static char *__psid_trans_to_raw_context(char *context)
{
	security_context_t raw_context;
	char *result;

	if (selinux_trans_to_raw_context(context, &raw_context))
		selerror("could not translate MLS label");
	PG_TRY();
	{
		result = pstrdup(raw_context);
	}
	PG_CATCH();
	{
		freecon(raw_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(raw_context);

	return result;
}

/* psid_in() -- PSID input function */
Datum
psid_in(PG_FUNCTION_ARGS)
{
	char *context = PG_GETARG_CSTRING(0);
	psid sid;

	context = __psid_trans_to_raw_context(context);
	sid = sepgsql_context_to_psid(context);

	PG_RETURN_OID(sid);
}

/* psid_out() -- PSID output function */
Datum
psid_out(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *context;

	context = sepgsql_psid_to_context(sid);
	context = __psid_raw_to_trans_context(context);

	PG_RETURN_CSTRING(context);
}

/* text_to_psid() -- PSID cast function */
Datum
text_to_psid(PG_FUNCTION_ARGS)
{
	text *tmp = PG_GETARG_TEXT_P(0);
	char *context;
	psid sid;

	context = VARDATA(tmp);
	context = __psid_trans_to_raw_context(context);
	sid = sepgsql_context_to_psid(context);

	PG_RETURN_OID(sid);
}

/* psid_to_text() -- PSID cast function */
Datum
psid_to_text(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *context;
	text *result;

	context = sepgsql_psid_to_context(sid);
	context = __psid_raw_to_trans_context(context);

	result = palloc(VARHDRSZ + strlen(context));
	VARATT_SIZEP(result) = VARHDRSZ + strlen(context);
	memcpy(VARDATA(result), context, strlen(context));

	PG_RETURN_TEXT_P(result);
}

