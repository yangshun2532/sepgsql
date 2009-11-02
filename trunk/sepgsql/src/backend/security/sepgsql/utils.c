/*
 * src/backend/security/sepgsql/utils.c
 *
 * SE-PostgreSQL support functions
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"


/*
 * sepgsql_getcon
 *
 * It returns client's security context
 */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
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

/*
 * sepgsql_database_getcon
 *
 * It returns security context of the given database
 */
Datum
sepgsql_database_getcon(PG_FUNCTION_ARGS)
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

	PG_RETURN_TEXT_P(CStringGetTextDatum(context));
}

/*
 * sepgsql_database_defcon
 *
 * It returns a default security context of a new database
 */
Datum
sepgsql_database_defcon(PG_FUNCTION_ARGS)
{
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	context = sepgsql_default_database_context();
	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}

Datum
sepgsql_schema_getcon(PG_FUNCTION_ARGS)
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
				(errcode(ERRCODE_UNDEFINED_DATABASE),
				 errmsg("cache lookup failed for database %u", datOid)));

	datum = SysCacheGetAttr(NAMESPACEOID, tuple,
							Anum_pg_namespace_nspsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	PG_RETURN_TEXT_P(CStringGetTextDatum(context));
}

Datum
sepgsql_schema_defcon(PG_FUNCTION_ARGS)
{
	Oid		datOid = PG_GETARG_OID(0);
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	context = sepgsql_default_schema_context(datOid);
	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}

Datum
sepgsql_table_getcon(PG_FUNCTION_ARGS)
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
						   ObjectIdGetDatum(nspOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_DATABASE),
				 errmsg("cache lookup failed for table %u", relOid)));

	datum = SysCacheGetAttr(RELOID, tuple,
							Anum_pg_class_relsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	PG_RETURN_TEXT_P(CStringGetTextDatum(context));
}

Datum
sepgsql_table_defcon(PG_FUNCTION_ARGS)
{
	Oid		nspOid = PG_GETARG_OID(0);
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	context = sepgsql_default_table_context(nspOid);
	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}

Datum
sepgsql_column_getcon(PG_FUNCTION_ARGS)
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

	tuple = SearchSysCache(ATTNAME,
						   ObjectIdGetDatum(relOid),
						   Int16GetDatum(attnum),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_DATABASE),
				 errmsg("cache lookup failed for database %u", datOid)));

	datum = SysCacheGetAttr(NAMESPACEOID, tuple,
							Anum_pg_attribute_attsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	PG_RETURN_TEXT_P(CStringGetTextDatum(context));
}

Datum
sepgsql_column_defcon(PG_FUNCTION_ARGS)
{
	Oid		relOid = PG_GETARG_OID(0);
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled now")));

	context = sepgsql_default_attribute_context(relOid);
	context = sepgsql_mcstrans_out(context);

	return CStringGetTextDatum(context);
}
