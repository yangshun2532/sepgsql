/*
 * src/backend/security/sepgsql/hooks.c
 * 
 * SE-PgSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_attribute.h"
#include "catalog/pg_database.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "utils/syscache.h"

/************************************************************
 *
 * Pg_database related security hooks
 *
 ************************************************************/

static bool
sepgsql_database_common(Oid datOid, uint32 required, bool abort)
{
	HeapTuple	tuple;
	Datum		datsecon;
	bool		rc, isnull;
	char	   *context = NULL;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database %u", datOid);

	datsecon = SysCacheGetAttr(DATABASEOID, tuple,
							   Anum_pg_database_datsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datsecon);

	/*
	 * If the database does not have any valid security context,
	 * we uses system's "unlabeled" context as a fallback.
	 */
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	rc = sepgsql_compute_perms(sepgsql_get_client_context(),
							   context,
							   SEPG_CLASS_DB_DATABASE,
							   required,
							   get_database_name(datOid), abort);
	ReleaseSysCache(tuple);

	return rc;
}

Datum
sepgsql_database_create(const char *datName, DefElem *datLabel)
{
	if (!sepgsql_is_enabled())
	{
		/* we don't allow SECURITY_CONTEXT option with SE-PgSQL disabled */
		if (datLabel)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SE-PostgreSQL is disabled")));

		return PointerGetDatum(NULL);
	}

	/*
	 * If client gives an explicit security context, 
	 *
	 *
	 */
	if (datLabel)
		context = sepgsql_mcstrans_in(strVal(datLabel->arg));
	else
	{
		context = sepgsql_compute_create(sepgsql_get_client_context(),
										 sepgsql_get_file_context(DataDir),
										 SEPG_CLASS_DB_DATABASE);
	}

	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__CREATE,
						  datName, true);

	return CStringGetTextDatum(context);
}

void
sepgsql_database_alter(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__SETATTR, true);
}

void
sepgsql_database_drop(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__DROP, true);
}

Datum
sepgsql_database_relabel(Oid datOid, DefElem *datLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
	{
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled")));
	}

	context = sepgsql_mcstrans_in(strVal(datLabel->arg));

	/* check db_database:{setattr relabelfrom} on the older context */
	sepgsql_database_common(datOid,
							SEPG_DB_DATABASE__SETATTR |
							SEPG_DB_DATABASE__RELABELFROM, true);

	/* check db_database:{relabelto} on the newer context */
	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__RELABELTO,
						  get_database_name(datOid), true);

	return CStringGetTextDatum(context);
}

void
sepgsql_database_grant(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__SETATTR, true);
}

void
sepgsql_database_access(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__ACCESS, true);
}

bool
sepgsql_database_superuser(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return true;

	return sepgsql_database_common(datOid, SEPG_DB_DATABASE__SUPERUSER, false);
}

void
sepgsql_database_load_module(Oid datOid, const char *filename)
{
	HeapTuple	tuple;
	Datum		datsecon;
	bool		isnull;
	char	   *dcontext, *fcontext;

	if (!sepgsql_is_enabled())
		return;

	/*
	 * we don't check to load modules due to the shared_preload_libraries
	 * setting, because it is not a request from client.
	 * Correctness of postgresql.conf is out of the scope in SE-PgSQL.
	 */
	if (GetProcessingMode() == InitProcessing)
		return;

	/*
	 * Fetch security context of the database
	 */
	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database %u", datOid);

	datsecon = SysCacheGetAttr(DATABASEOID, tuple,
							   Anum_pg_database_datsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datsecon);
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	ReleaseSysCache(tuple);

	/*
	 * Fetch security context of the module
	 */
	fcontext = sepgsql_get_file_context(filename);

	/*
	 * Check db_database:{load_module} on a pair of database and module
	 */
	sepgsql_compute_perms(dcontext, fcontext,
						  SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__LOAD_MODULE,
						  get_database_name(datOid), true);
}

/************************************************************
 *
 * Pg_namespace related security hooks
 *
 ************************************************************/
static bool
sepgsql_schema_common(Oid nspOid, uint32 required, bool abort)
{
	HeapTuple	tuple;
	Datum		nspsecon;
	bool		rc, isnull;
	char	   *context = NULL;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nspOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace %u", nspOid);

	nspsecon = SysCacheGetAttr(NAMESPACEOID, tuple,
							   Anum_pg_namespace_nspsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(nspsecon);

	/*
	 * If the database does not have any valid security context,
	 * we uses system's "unlabeled" context as a fallback.
	 */
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	rc = sepgsql_compute_perms(sepgsql_get_client_context(),
							   context,
							   SEPG_CLASS_DB_SCHEMA,
							   required,
							   get_namespace_name(nspOid), abort);
	ReleaseSysCache(tuple);

	return rc;
}

Datum
sepgsql_schema_create(const char *nspName, bool isTemp, DefElem *nspLabel)
{
	if (!sepgsql_is_enabled())
	{
		/* we don't allow SECURITY_CONTEXT option with SE-PgSQL disabled */
		if (nspLabel)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SE-PostgreSQL is disabled")));

		return PointerGetDatum(NULL);
	}

	if (nspLabel)
		context = sepgsql_mcstrans_in(strVal(nspLabel->arg));
	else
		context = sepgsql_default_schema_context(MyDatabaseId);

	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_SCHEMA,
						  SEPG_DB_SCHEMA__CREATE,
						  nspName, true);

	return CStringGetTextDatum(context);
}

void
sepgsql_schema_alter(Oid nspOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SETATTR, true);
}

void
sepgsql_schema_drop(Oid nspOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__DROP, true);
}

Datum
sepgsql_schema_relabel(Oid nspOid, DefElem *nspLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
	{
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled")));
	}

	context = sepgsql_mcstrans_in(strVal(datLabel->arg));

	/* check db_schema:{setattr relabelfrom} on the older context */
	sepgsql_database_common(nspOid,
							SEPG_DB_SCHEMA__SETATTR |
							SEPG_DB_SCHEMA__RELABELFROM, true);

	/* check db_schema:{relabelto} on the newer context */
	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_SCHEMA,
						  SEPG_DB_SCHEMA__RELABELTO,
						  get_namespace_name(nspOid), true);

	return CStringGetTextDatum(context);
}

void
sepgsql_schema_grant(Oid nspOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SETATTR, true);
}

bool
sepgsql_schema_search(Oid nspOid, bool abort)
{
	if (!sepgsql_is_enabled())
		return true;

	/*
	 * We always allow to search on temporary schemas, because it is
	 * actually 
	 */
	if (isTempNamespace(nspOid))
		return true;

	return sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SEARCH, false);
}

/************************************************************
 *
 * Pg_class related security hooks
 *
 ************************************************************/
static bool
sepgsql_relation_common(Oid relOid, uint32 required, bool abort)
{}

Datum *
sepgsql_relation_create(const char *relName,
						char relkind,
						TupleDesc tupDesc,
						Oid nspOid,
						DefElem *relLabel,
						List *colList,
						bool createAs)
{}

void
sepgsql_relation_alter(Oid relOid, const char *newName, Oid newNsp)
{}

void
sepgsql_relation_drop(Oid relOid)
{}

void
sepgsql_relation_grant(Oid relOid)
{}

Datum
sepgsql_relation_relabel(Oid relOid, DefElem *relLabel)
{}

void
sepgsql_relation_truncate(Relation rel)
{}

void
sepgsql_relation_references(Relation pkRel, int16 *pkAttrs,
							Relation fkRel, int16 *fkAttrs, int natts)
{}

void
sepgsql_relation_lock(Oid relOid)
{}

void
sepgsql_index_create(Oid relOid, Oid nspOid)
{
}





/************************************************************
 *
 * Pg_attribute related security hooks
 *
 ************************************************************/




/************************************************************
 *
 * Misc objects related security hooks
 *
 ************************************************************/
void
sepgsql_object_drop(ObjectAddress *object)
{
	if (!sepgsql_is_enabled())
		return;

	switch (getObjectClass(object))
	{
	case OCLASS_CLASS:
		if (object->objectSubId == 0)
			sepgsql_relation_drop(object->objectId);
		else
			sepgsql_attribute_drop(object->objectId,
								   object->objectSubId);
		break;

	case OCLASS_DATABASE:	/* should not be happen */
	case OCLASS_SCHEMA:		/* should not be happen */
	default:
		/* do nothing */
		break;
	}
}



