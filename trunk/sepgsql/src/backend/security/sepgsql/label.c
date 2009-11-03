/*
 * src/backend/security/sepgsql/label.c
 * 
 * Routines to manage security context
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

#include <selinux/selinux.h>

/* GUC option to turn on/off mcstrans feature */
bool	sepostgresql_mcstrans;

/*
 * sepgsql_default_database_context
 *
 *
 *
 */
char *
sepgsql_default_database_context(void)
{
	return sepgsql_compute_create(sepgsql_get_client_context(),
								  sepgsql_get_client_context(),
								  //sepgsql_get_file_context(DataDir),
								  SEPG_CLASS_DB_DATABASE);
}

/*
 * sepgsql_default_schema_context
 *
 *
 *
 */
char *
sepgsql_default_schema_context(Oid datOid)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *context = NULL;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		datum = SysCacheGetAttr(DATABASEOID, tuple,
								Anum_pg_database_datsecon, &isnull);
		if (!isnull)
			context = TextDatumGetCString(datum);

		ReleaseSysCache(tuple);
	}

	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	return sepgsql_compute_create(sepgsql_get_client_context(),
								  context,
								  SEPG_CLASS_DB_SCHEMA);
}

/*
 * sepgsql_default_table_context
 *
 *
 *
 */
char *
sepgsql_default_table_context(Oid nspOid)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *context = NULL;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nspOid),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		datum = SysCacheGetAttr(NAMESPACEOID, tuple,
								Anum_pg_namespace_nspsecon, &isnull);
		if (!isnull)
			context = TextDatumGetCString(datum);

		ReleaseSysCache(tuple);
	}

	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	return sepgsql_compute_create(sepgsql_get_client_context(),
								  context,
								  SEPG_CLASS_DB_TABLE);
}

/*
 * sepgsql_default_column_context
 *
 *
 *
 *
 */
char *
sepgsql_default_column_context(Oid relOid)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *context = NULL;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relOid),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		datum = SysCacheGetAttr(RELOID, tuple,
								Anum_pg_class_relsecon, &isnull);
		if (!isnull)
			context = TextDatumGetCString(datum);

		ReleaseSysCache(tuple);
	}

	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	return sepgsql_compute_create(sepgsql_get_client_context(),
								  context,
								  SEPG_CLASS_DB_COLUMN);
}

/*
 * sepgsql_get_client_context
 *
 * It returns the security context of the client which was set up
 * in the initialization steps.
 */
static char *client_context = NULL;

char *
sepgsql_get_client_context(void)
{
	return client_context;
}

/*
 * sepgsql_set_client_context
 *
 * It set the given security context as a client's one, and returns
 * the original one. The given context has to alive in the duration
 * to be applied. In other word, the caller need to pay attention
 * about MemoryContext of the given context allocated.
 */
char *
sepgsql_set_client_context(char *new_context)
{
	char   *old_context = client_context;

	client_context = new_context;

	return old_context;
}

/*
 * sepgsql_get_unlabeled_context
 *
 * It returns the "unlabeled" security context.
 * This context is applied when the target object is unlabeled or valid
 * security context as an alternative.
 * The security policy gives the unlabeled context, and it is typically
 * "system_u:object_r:unlabeled_t:s0" in the default.
 */
char *
sepgsql_get_unlabeled_context(void)
{
	char   *unlabeled_con;
	char   *result;

	if (security_get_initial_context_raw("unlabeled", &unlabeled_con) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: could not get \"unlabeled\" context")));
	/*
	 * libselinux returns a malloc()'ed regison, so we need to duplicate
	 * it on the palloc()'ed region.
	 */
	PG_TRY();
	{
		result = pstrdup(unlabeled_con);
	}
	PG_CATCH();
	{
		freecon(unlabeled_con);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(unlabeled_con);

	return result;
}

/*
 * sepgsql_get_file_context
 *
 * It returns the security context of the given filename.
 */
char *
sepgsql_get_file_context(const char *filename)
{
	char   *file_context;
	char   *result;

	if (getfilecon(filename, &file_context) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not get security context of \"%s\": %m",
						filename)));
	/*
	 * libselinux returns a malloc()'ed regison, so we need to duplicate
	 * it on the palloc()'ed region.
	 */
	PG_TRY();
	{
		result = pstrdup(file_context);
	}
	PG_CATCH();
	{
		freecon(file_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(file_context);

	return result;
}

/*
 * sepgsql_mcstrans_in
 *
 * It translates the given security context in human readable format into
 * its raw format, if sepostgresql_mcstrans is turned on.
 * If turned off, it returned the given string as is.
 *
 * Example)
 *   system_u:object_r:sepgsql_table_t:Unclassified (human readable)
 *
 *    --> system_u:object_r:sepgsql_table_t:s0 (raw format)
 */
char *
sepgsql_mcstrans_in(char *trans_context)
{
	char	   *raw_context;
	char	   *result;

	if (!sepostgresql_mcstrans)
		return trans_context;

	if (selinux_trans_to_raw_context(trans_context, &raw_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: failed to translate \"%s\"", trans_context)));
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

/*
 * sepgsql_mcstrans_out
 *
 * It translate the given security context in raw format into its human
 * readable format, if sepostgresql_mcstrans is turned on.
 * If turned off, it returns the given string as is.
 *
 * Example)
 *   system_u:object_r:sepgsql_table_t:s0:c0 (raw format)
 *
 *    --> system_u:object_r:sepgsql_table_t:Classified (human readable)
 */
char *
sepgsql_mcstrans_out(char *raw_context)
{
	char	   *trans_context;
	char	   *result;

	if (!sepostgresql_mcstrans)
		return raw_context;

	if (selinux_raw_to_trans_context(raw_context, &trans_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux: failed to translate \"%s\"", raw_context)));
	PG_TRY();
	{
		result = pstrdup(trans_context);
	}
	PG_CATCH();
	{
		freecon(trans_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(trans_context);

	return result;
}
