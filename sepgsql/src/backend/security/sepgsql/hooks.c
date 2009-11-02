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

/* ---- static declarations ---- */
static bool sepgsql_database_common(Oid datOid, uint32 required, bool abort);
static bool sepgsql_schema_common(Oid nspOid, uint32 required, bool abort);
static bool sepgsql_relation_common(Oid relOid, uint32 required, bool abort);

/************************************************************
 *
 * Pg_database related security hooks
 *
 ************************************************************/

/*
 * sepgsql_database_common
 *
 * A helper function to check required permissions on a pair of the client
 * and the given database.
 */
static bool
sepgsql_database_common(Oid datOid, uint32 required, bool abort)
{
	HeapTuple	tuple;
	Datum		datsecon;
	bool		rc, isnull;
	char	   *audit_name;
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

	audit_name = NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname);
	rc = sepgsql_compute_perms(sepgsql_get_client_context(),
							   context,
							   SEPG_CLASS_DB_DATABASE,
							   required,
							   audit_name, abort);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsql_database_create
 *
 * It checks client's privilege to create a new database, and returns
 * a security context (in raw-format) to be assigned on. 
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to handle CREATE DATABASE
 * statement, then the caller has to assign the returned context on the
 * new database.
 *
 * If no explicit security context is given, it compute a default security
 * context of the new database. Then, it checks db_database:{create}
 * permission on the pair of client's context and the default context.
 * If an explicit one is given, it shall be applied instead of the
 * default one after the sanity and validation checks.
 * 
 * datName : name of the new database
 * datLabel : an explicit security context, or NULL
 */
Datum
sepgsql_database_create(const char *datName, DefElem *datLabel)
{
	if (!sepgsql_is_enabled())
	{
		/*
		 * We don't allow SECURITY_CONTEXT option without
		 * SE-PgSQL enaled.
		 */
		if (datLabel)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SE-PostgreSQL is disabled")));

		return PointerGetDatum(NULL);
	}

	/*
	 * If an explicit security context is given, we apply it with
	 * translation into raw format (when mcstrans is enabled).
	 * Otherwise, we compute a default security context of the new
	 * database.
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

	/*
	 * The checked security context should be returned to caller.
	 * Caller has to assign it on the new database.
	 */
	return CStringGetTextDatum(context);
}

/*
 * sepgsql_database_alter
 *
 * It checks client's privilege to alter a certain database.
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to handle ALTER DATABASE
 * statement. It modifies metadata of the database, so we need to check
 * db_database:{setattr} permission on a pair of client and the database.
 *
 * datOid : OID of the database to be altered
 */
void
sepgsql_database_alter(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__SETATTR, true);
}

/*
 * sepgsql_database_drop
 *
 * It checks client's privilege to drop a certain database.
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to handle DROP DATABASE
 * statement. It drops the database itself, so we need to check
 * db_database:{drop} permission on a pair of client and the database.
 *
 * datOid : OID of the database to be dropped
 */
void
sepgsql_database_drop(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__DROP, true);
}

/*
 * sepgsql_database_relabel
 *
 * It checks client's privilege to change security context of a certain
 * database. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle ALTER DATABASE
 * statement with SECURITY_CONTEXT option. It modifies a special metadata,
 * so it requires two more permissions, not only db_database:{setattr}.
 * It checks db_database:{relabelfrom} permission on the older security
 * context of the database, and db_database:{relabelto} on the newer
 * security context to be assigned on.
 *
 * This hook also applies validation check on the given security context
 * and translates it into raw-format. The caller has to assign the returned
 * security context on the target database correctly.
 *
 * datOid : OID of the target database
 * datLabel : An explicit security context to be assigned on
 */
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

/*
 * sepgsql_database_grant
 *
 * It checks client's privilege to grant/revoke permissions on a certain
 * database. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle GRANT/REVOKE statement
 * on databases. It also modifies metadata of the database, so we need to
 * check db_database:{setattr} permission on a pair of client and the database.
 *
 * datOid : OID of the database to be altered
 */
void
sepgsql_database_grant(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__SETATTR, true);
}

/*
 * sepgsql_database_access
 *
 * It checks client's privilege to access to the selected database just after
 * ACL_CONNECT checks in the default PG model.
 *
 * datOid : OID of the database to be accessed
 */
void
sepgsql_database_access(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_database_common(datOid, SEPG_DB_DATABASE__ACCESS, true);
}

/*
 * sepgsql_database_superuser
 *
 * It checks client's privilege to perform as a database superuser on
 * a certain database. If violated, it returns false. In this case,
 * the caller has to prevent caller performs as a database superuser.
 * Otherwise, it follows the configuration in the default PG model.
 *
 * This hook should be called on the test whether user has database
 * superuser privilege, or not. It checks db_database:{superuser}
 * permission on the pair of client and database.
 *
 * datOid : OID of the database (maybe equal to MyDatabaseId)
 */
bool
sepgsql_database_superuser(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return true;

	return sepgsql_database_common(datOid, SEPG_DB_DATABASE__SUPERUSER, false);
}

/*
 * sepgsql_database_load_module
 *
 * It checks database's capability to load a binary module into the
 *
 *
 *
 *
 */
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

/*
 * sepgsql_schema_common
 *
 * A helper function to check required permissions on a pair of the client
 * and the given schema
 */
static bool
sepgsql_schema_common(Oid nspOid, uint32 required, bool abort)
{
	HeapTuple	tuple;
	Datum		nspsecon;
	bool		rc, isnull;
	char	   *audit_name;
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

	audit_name = NameStr(((Form_pg_namespace) GETSTRUCT(tuple))->nspname);
	rc = sepgsql_compute_perms(sepgsql_get_client_context(),
							   context,
							   SEPG_CLASS_DB_SCHEMA,
							   required,
							   audit_name, abort);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsql_schema_create
 *
 * It checks client's privilege to create a new schema, and returns
 * a security context (in raw-format) to be assigned on. 
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to handle CREATE SCHEMA or
 * to create a temporary schema, then the caller has to assign the returned
 * context on the new schema.
 *
 * If no explicit security context is given, it compute a default security
 * context of the new schema. Then, it checks db_schema:{create} permission
 * on the pair of client's context and the default context.
 * If an explicit one is given, it shall be applied instead of the default
 * one after the sanity and validation checks.
 * 
 * nspName : name of the new schema
 * isTemp : true, if creation of the temporary schema
 * nspLabel : an explicit security context, or NULL
 */
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

/*
 * sepgsql_database_alter
 *
 * It checks client's privilege to alter a certain schema.
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to handle ALTER SCHEMA
 * statement. It modifies metadata of the schema, so we need to check
 * db_schema:{setattr} permission on a pair of client and the schema.
 *
 * nspOid : OID of the schema to be altered
 */
void
sepgsql_schema_alter(Oid nspOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SETATTR, true);
}

/*
 * sepgsql_schema_drop
 *
 * It checks client's privilege to drop a certain schema.
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to handle DROP SCHEMA
 * statement. Note that we don't need to check anything on cleaning up
 * temporary schema after the session closed, because it is a purely
 * internal process.
 *
 * It drops an existing schema, so we need to check db_schema:{setattr}
 * permission on a pair of client and the schema.
 *
 * nspOid : OID of the schema to be dropped
 */
void
sepgsql_schema_drop(Oid nspOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__DROP, true);
}

/*
 * sepgsql_schema_relabel
 *
 * It checks client's privilege to change security context of a certain
 * schema. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle ALTER SCHEMA
 * statement with SECURITY_CONTEXT option. It modifies a special metadata,
 * so it requires two more permissions, not only db_schema:{setattr}.
 * It checks db_schema:{relabelfrom} permission on the older security
 * context of the schema, and db_schema:{relabelto} on the newer one
 * to be assigned on.
 *
 * This hook also applies validation check on the given security context
 * and translates it into raw-format. The caller has to assign the returned
 * security context on the target schema correctly.
 *
 * nspOid : OID of the target schema
 * nspLabel : An explicit security context to be assigned on
 */
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
	sepgsql_schema_common(nspOid,
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

/*
 * sepgsql_schema_grant
 *
 * It checks client's privilege to grant/revoke permissions on a certain
 * schema. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle GRANT/REVOKE statement
 * on schema. It also modifies metadata of the schema, so we need to check
 * db_schema:{setattr} permission on a pair of client and the schema.
 *
 * nspOid : OID of the schema to be altered
 */
void
sepgsql_schema_grant(Oid nspOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__SETATTR, true);
}

/*
 * sepgsql_schema_search
 *
 * It checks client's privilege to resolve lookup database objects within
 * a certain schema. If violated, it raised an error or returns false,
 * depending on the second argument (abort).
 * If it returned false, the caller has to drop the given schema from
 * schema search path correctly.
 *
 * This hook should be called on (re)computing schema search path or
 * looking up a database object with an explicit namespace.
 *
 * nspOid : OID of the schema to be searched
 * abort : True, if caller want to raise an error on access violation.
 */
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

/*
 * sepgsql_relation_common
 *
 * A helper function to check required permissions on a pair of the client
 * and the given relation
 */
static bool
sepgsql_relation_common(Oid relOid, uint32 required, bool abort)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		rc, isnull;
	char		relkind;
	char	   *audit_name;
	char	   *context = NULL;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", relOid);

	relkind = ((Form_pg_class) GETSTRUCT(tuple))->relkind;

	if (relkind != RELKIND_RELATION)
	{
		ReleaseSysCache(tuple);
		return true;
	}

	context = SysCacheGetAttr(RELOID, tuple,
							  Anum_pg_class_relsecon, &isnull);
	if (!isnull || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	audit_name = NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname);
	rc = sepgsql_compute_perms(sepgsql_get_client_context(),
							   context,
							   SEPG_CLASS_DB_TABLE,
							   required, 
							   audit_name, abort);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsql_relation_create
 *
 * It checks client's privilege to create a new table and columns owned
 * by the table, and returns an array of security contexts to be assigned
 * on the table/columns.
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to create a new regular
 * table, but no need to 
 *
 *
 *
 *
 * relName : name of the new relation
 * relkind : relkind to be assigned on
 * tupDesc : TupleDesc of the new relation.
 * nspOid : OID of the namespace which owns the new relation
 * relLabel : 
 * colList : 
 * createAs : True, if the new table created by 
 */
Datum *
sepgsql_relation_create(const char *relName,
						char relkind,
						TupleDesc tupDesc,
						Oid nspOid,
						DefElem *relLabel,
						List *colList,
						bool createAs)
{
	ListCell   *l;
	Datum	   *result;
	char	   *context;
	uint16		tclass;
	uint32		required;


	/*
	 * We don't allow SECURITY_CONTEXT option without SE-PgSQL enabled
	 */
	if (!sepgsql_is_enabled())
	{
		if (datLabel)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("SE-PostgreSQL is disabled")));

		foreach (l, colList)
		{
			ColumnDef  *cdef = (ColumnDef *) lfirst(l);

			if (cdef->inhcount == 0 && cdef->secontext)
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("SE-PostgreSQL is disabled")));
		}
		return NULL;
	}



	/*
	 * No need to check anything on 
	 *
	 */
	if (relkind != RELKIND_RELATION)
		return NULL;

	if (!relLabel)
		context = sepgsql_default_table_context(nspOid);
	else
	{
		
		
	}
	{
		
		
	}
	else
	{
		
		
	}
	tclass = SEPG_CLASS_DB_TABLE;
	required = SEPG_DB_TABLE__CREATE;
	if (createAs)
		required |= SEPG_DB_TABLE__INSERT;
	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context, tclass, required, relName, true);


extern bool
	sepgsql_compute_perms(char *scontext, char *tcontext,
						  uint16 tclass, uint32 required,
						  const char *audit_name, bool abort)
	/*
	 * The result array contains security contexts to be assigned on
	 * the new table and columns. The result[0] stores the security
	 * context of the table.
	 * And, result[attnum - FirstLowInvalidHeapAttributeNumber] stores
	 * the security context of the column with this attribute number.
	 */
	result = palloc0(sizeof(Datum) * (tupDesc->natts
					 - FirstLowInvalidHeapAttributeNumber));
	
















}

/*
 * sepgsql_relation_alter
 *
 * It checks client's privilege to alter a certain relation.
 * If violated, it raises an error.
 *
 * This hook should be called on the routine to handle ALTER TABLE
 * statement. It modifies metadata of the table, so we need to check
 * db_table:{setattr} permission on a pair of client and the relation.
 * In addition, a few ALTER TABLE options enables to affect to the
 * namespace, so we also need to check db_schema:{add_name} and
 * db_schema:{remove_name} permission on corresponding schemas.
 *
 * relOid : OID of the relation to be altered
 * newName : New name of the relation, if exist
 * newNsp : Name schema of the relation, if exist
 */
void
sepgsql_relation_alter(Oid relOid, const char *newName, Oid newNsp)
{
	char   *context;

	if (!sepgsql_is_enabled())
		return;

	sepgsql_relation_common(relOid, SEPG_DB_TABLE__SETATTR, true);

	if (newName)
		sepgsql_schema_common(get_rel_namespace(relOid),
							  SEPG_DB_SCHEMA__ADD_NAME |
							  SEPG_DB_SCHEMA__REMOVE_NAME, true);
	if (newNsp)
	{
		sepgsql_schema_common(get_rel_namespace(relOid),
							  SEPG_DB_SCHEMA__REMOVE_NAME, true);
		sepgsql_schema_common(newNsp, SEPG_DB_SCHEMA__ADD_NAME, true);
	}
}

/*
 * sepgsql_relation_drop
 *
 * It checks client's privilege to drop a certain relation.
 * If violated, it raises an error.
 *
 * This hook should be called when user's query tries to drop a cerain
 * table, including cascaded deletions, not only DROP TABLE statement.
 *
 * It checks db_table:{drop} permission, if the given relation is a
 * regular table (RELKIND_RELATION). Otherwise, it does not apply
 * any checks.
 *
 * relOid : OID of the relation to be dropped
 */
void
sepgsql_relation_drop(Oid relOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_relation_common(relOid, SEPG_DB_TABLE__DROP, true);
}

/*
 * sepgsql_relation_grant
 *
 * It checks client's privilege to grant/revoke permissions on a certain
 * relation. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle GRANT/REVOKE statement
 * on relations. It also modifies metadata of the relation, so we need to
 * check db_table:{setattr} permission on a pair of client and the table.
 *
 * relOid : OID of the relation to be altered
 */
void
sepgsql_relation_grant(Oid relOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_relation_common(relOid, SEPG_DB_TABLE__SETATTR, true);
}

/*
 * sepgsql_relation_relabel
 *
 * It checks client's privilege to change security context of a certain
 * relation. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle ALTER TABLE
 * statement with SECURITY_CONTEXT option. It modifies a special metadata,
 * so it requires two more permissions, not only db_table:{setattr}.
 * It also checks db_table:{relabelfrom} permission on the older security
 * context of the table, and db_table:{relabelto} on the newer one
 * to be assigned on.
 *
 * This hook also applies validation check on the given security context
 * and translates it into raw-format. The caller has to assign the returned
 * security context on the target table correctly.
 *
 * relOid : OID of the target schema
 * relLabel : An explicit security context to be assigned on
 */
Datum
sepgsql_relation_relabel(Oid relOid, DefElem *relLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
	{
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled")));
	}

	context = sepgsql_mcstrans_in(strVal(datLabel->arg));

	/* check db_table:{setattr relabelfrom} on the older context */
	sepgsql_relation_common(relOid,
							SEPG_DB_TABLE__SETATTR |
							SEPG_DB_TABLE__RELABELFROM, true);

	/* check db_table:{relabelto} on the newer context */
	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_TABLE,
						  SEPG_DB_TABLE__RELABELTO,
						  get_namespace_name(nspOid), true);

	return CStringGetTextDatum(context);
}

/*
 * sepgsql_relation_truncate
 *
 * It checks client's privilege to truncate contents of the given table.
 * If violated, it raises an error.
 *
 * This hook should be called on truncate_check_rel() which also checks
 * permission in the default PG model.
 *
 * rel : Relation object to be truncated
 */
void
sepgsql_relation_truncate(Relation rel)
{
	if (!sepgsql_is_enabled())
		return;

	
}

/*
 * sepgsql_relation_lock
 *
 * It checks client's privilege to lock a certain table explicitly.
 * If violated, it raises an error.
 *
 * Note that db_table:{lock} parmission is not checked on implicit
 * locks due to the regular operations. This hook should be called
 * from the routine to handle LOCK statement.
 *
 * relOid : OID of the relation to be locked explicitly
 */
void
sepgsql_relation_lock(Oid relOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_relation_common(relOid, SEPG_DB_TABLE__LOCK, true);
}

/*
 * sepgsql_index_create
 *
 * It checks client's privilege to create an index on a certain table.
 * If violated, it raises an error.
 *
 * We consider an index a part of properties of table, so we checks
 * db_table:{setattr} permission on the table to be indexed here.
 * In addition, it also add a name into the namespace, so db_schema:{add_name}
 * is also checked here.
 *
 * relOid : OID of the relation to be indexed
 * nspOid : OID of the schema to be assigned
 */
void
sepgsql_index_create(Oid relOid, Oid nspOid)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_relation_common(relOid, SEPG_DB_TABLE__SETATTR, true);
	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);
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

/*
 * sepgsql_object_comment
 *
 * It checks client's privilege to comment on a certain database object.
 * If violated, it raises an error.
 * Every entries within pg_description/pg_shdepend are considered as
 * a part of properties of the database object commented.
 * So, we checks db_xxx:{setattr} permission (it controls modification
 * of the metadata) on a pair of the client and the database object to
 * be commented on.
 *
 * This hook should be called from CreateComments() or CreateSharedComments().
 * If client tries to comment on the managed object, it checks appropriate
 * permission.
 *
 * relOid : OID of the catalog which owns the target object
 * objId : OID of the database object to be commented on
 * subId : If a column, attribute number to be commented on
 */
void
sepgsql_object_comment(Oid relOid, Oid objId, int32 subId)
{
	switch (relOid)
	{
	case DatabaseRelationId:
		sepgsql_database_common(objId, SEPG_DB_DATABASE__SETATTR, true);
		break;

	case NamespaceRelationId:
		sepgsql_schema_common(objId, SEPG_DB_SCHEMA__SETATTR, true);
		break;

	case RelationRelationId:
		if (subId == 0)
			sepgsql_relation_common(objId, SEPG_DB_TABLE__SETATTR, true);
		else
			sepgsql_attribute_common();
		break;

	default:
		/* do nothing */
		break;
	}
}

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
