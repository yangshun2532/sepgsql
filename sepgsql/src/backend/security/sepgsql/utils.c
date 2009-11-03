/*
 * src/backend/security/sepgsql/utils.c
 *
 * SE-PostgreSQL support functions
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/syscache.h"

#include <selinux/selinux.h>

/*
 * sepgsql_fn_getcon
 *
 * It returns client's security context
 */
Datum
sepgsql_fn_getcon(PG_FUNCTION_ARGS)
{
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	context = sepgsql_get_client_context();
	context = sepgsql_mcstrans_out(context);
	return CStringGetTextDatum(context);
}

Datum
sepgsql_fn_database_getcon(PG_FUNCTION_ARGS)
{
	Oid			datOid = PG_GETARG_OID(0);
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *context = NULL;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_DATABASE),
				 errmsg("cache lookup failed for database %u", datOid)));

	datum = SysCacheGetAttr(DATABASEOID, tuple,
							Anum_pg_database_datsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
    if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}

Datum
sepgsql_fn_schema_getcon(PG_FUNCTION_ARGS)
{
	Oid			nspOid = PG_GETARG_OID(0);
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *context = NULL;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nspOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_SCHEMA),
				 errmsg("schema with OID %u does not exist", nspOid)));

	datum = SysCacheGetAttr(NAMESPACEOID, tuple,
							Anum_pg_namespace_nspsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}

Datum
sepgsql_fn_table_getcon(PG_FUNCTION_ARGS)
{
	Oid			relOid = PG_GETARG_OID(0);
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *context = NULL;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_TABLE),
				 errmsg("relation with OID %u does not exist", relOid)));

	datum = SysCacheGetAttr(RELOID, tuple,
							Anum_pg_class_relsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}

Datum
sepgsql_fn_column_getcon(PG_FUNCTION_ARGS)
{
	Oid			relOid = PG_GETARG_OID(0);
	AttrNumber	attnum = PG_GETARG_INT16(1);
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *context = NULL;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relOid),
						   Int16GetDatum(attnum),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_COLUMN),
				 errmsg("attribute %d of relation with OID %u does not exist",
						relOid, attnum)));

	datum = SysCacheGetAttr(ATTNUM, tuple,
							Anum_pg_attribute_attsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}

/*
 * sepgsql_fn_compute_create
 *
 */
Datum
sepgsql_fn_compute_create(PG_FUNCTION_ARGS)
{
	char   *scontext = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char   *tcontext = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	char   *tclass_name = TextDatumGetCString(PG_GETARG_TEXT_P(2));
	char   *ncontext;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	scontext = sepgsql_mcstrans_in(scontext);
	if (security_check_context_raw(scontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("Invalid security context \"%s\"", scontext)));

	tcontext = sepgsql_mcstrans_in(tcontext);
	if (security_check_context_raw(tcontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("Invalid security context \"%s\"", scontext)));

	ncontext = sepgsql_compute_create_name(scontext, tcontext, tclass_name);
	ncontext = sepgsql_mcstrans_out(ncontext);

	return CStringGetTextDatum(ncontext);
}
