/*
 * src/backend/security/sepgsql/hooks.c
 * 
 * SE-PgSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/sysattr.h"
#include "catalog/heap.h"
#include "catalog/namespace.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_database.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

#include <selinux/selinux.h>

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
bool
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
 * srcDatOid : OID of the template database
 * datLabel : an explicit security context, or NULL
 */
Value *
sepgsql_database_create(const char *datName, Oid srcDatOid, Node *datLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
		return NULL;

	/*
	 * If an explicit security context is given, we apply it with
	 * translation into raw format (when mcstrans is enabled).
	 * Otherwise, we compute a default security context of the new
	 * database.
	 */
	if (!datLabel)
		context = sepgsql_default_database_context(srcDatOid);
	else
	{
		Assert(IsA(datLabel, String));

		context = sepgsql_mcstrans_in(strVal(datLabel));
		if (security_check_context_raw(context) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
					 errmsg("invalid security context \"%s\"", context)));
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
	return makeString(context);
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
Value *
sepgsql_database_relabel(Oid datOid, Node *datLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled")));

	Assert(IsA(datLabel, String));

	context = sepgsql_mcstrans_in(strVal(datLabel));
	if (security_check_context_raw(context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("invalid security context \"%s\"", context)));

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

	return makeString(context);
}

/*
 * sepgsql_database_grant
 *
 * It checks client's privilege to grant/revoke permissions on a certain
 * database. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle GRANT/REVOKE
 * on databases. It modifies metadata of the database, so we need to
 * check db_database:{setattr} permission on a pair of client and
 * the database.
 *
 * datOid : OID of the database to be granted/revoked
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
 * It checks client's privilege to access to the selected database just
 * after ACL_CONNECT checks in the default PG privileges.
 * In this check, we must raise a fatal error on violation. 
 *
 * datOid : OID of the database to be accessed
 */
void
sepgsql_database_access(Oid datOid)
{
	if (!sepgsql_is_enabled())
		return;

	if (!sepgsql_database_common(datOid, SEPG_DB_DATABASE__ACCESS, false))
		ereport(FATAL,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("SELinux: security policy violation")));
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
bool
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
	 * If the schema does not have any valid security context,
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
 * to create a temporary schema, then the caller must assign the returned
 * security context on the new schema.
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
Value *
sepgsql_schema_create(const char *nspName, bool isTemp, Node *nspLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
		return NULL;

	if (!nspLabel)
		context = sepgsql_default_schema_context(MyDatabaseId);
	else
	{
		Assert(IsA(nspLabel, String));

		context = sepgsql_mcstrans_in(strVal(nspLabel));
		if (security_check_context_raw(context) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
					 errmsg("invalid security context \"%s\"", context)));
	}

	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_SCHEMA,
						  SEPG_DB_SCHEMA__CREATE,
						  nspName, true);

	return makeString(context);
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
Value *
sepgsql_schema_relabel(Oid nspOid, Node *nspLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled")));

	Assert(IsA(nspLabel, String));

	context = sepgsql_mcstrans_in(strVal(nspLabel));
	if (security_check_context_raw(context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("invalid security context \"%s\"", context)));

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

	return makeString(context);
}

/*
 * sepgsql_schema_grant
 *
 * It checks client's privilege to grant/revoke permissions on a certain
 * schema. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle GRANT/REVOKE
 * on schema. It also modifies metadata of the schema, so we need to check
 * db_schema:{setattr} permission on a pair of client and the schema.
 *
 * nspOid : OID of the schema to be granted/revoked
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
 * abort  : True, if caller want to raise an error on access violation.
 */
bool
sepgsql_schema_search(Oid nspOid, bool abort)
{
	if (!sepgsql_is_enabled())
		return true;

	/*
	 * We always allow to search on temporary schemas, because it is
	 * actually a schema, but it is an implementation details.
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
bool
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

	datum = SysCacheGetAttr(RELOID, tuple,
							Anum_pg_class_relsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	/*
	 * If the table does not have any valid security context,
	 * we uses system's "unlabeled" context as a fallback.
	 */
	if (!context || security_check_context_raw(context) < 0)
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
 * nu the table, and returns an array of security contexts to be assigned
 * on the table and columns. If violated, it raised an error.
 *
 * This hook should be called on the routine to create a new relation,
 * but not necessary to call from the following code path.
 *  - Boot_CreateStmt handler in bootparse.y.
 *    In the BootstrapProcessing mode, SE-PgSQL is disabled.
 *    It assigns a security context on tables later.
 *  - Creation of TOAST relation
 *    It is a quite internal process, and we don't assign a security
 *    context on the TOAST relation.
 *  - Creation of temporary relation to rebuild a certain relation
 *    It is a quite internal process, and it shall be dropped soon.
 *    We don't need apply any checks on its creation and deletion.
 *
 * At top-half of the function, it computes a default security context
 * or applies validation checks on the given context for the new table.
 * Then, it checks permissions to create a new table with the security
 * context. If this table is in creation due to SELECT INTO, we also
 * need to check db_table:{insert}, because it can also add new data
 * into the table contents.
 * 
 * At bottom-half of the function, it also computes a default security
 * context or applies validation checks on the given context for each
 * columns owned by the table (An explicit security context shall be
 * given via ColumnDef->secontext).
 * Note that we cannot use sepgsql_attribute_create() because the table
 * is not still under construction, so it is unavailable to obtain the
 * security context of the table owning new columns.
 *
 * It returns an array of the security contexts to be assigned on the
 * new table and columns, represented as Value objects.
 * 
 *   results[0] = Security context of the table
 *   results[attnum - FirstLowInvalidHeapAttributeNumber]
 *       = Security context of the column with this attribute number
 *
 * The caller must assign these security contexts correctly.
 *
 * relName : name of the new relation
 * relkind : relkind of the new relation.
 * tupDesc : TupleDesc of the new relation.
 * nspOid : OID of the schema which shall own the new relation
 * relLabel : an explicitly given table's security context, or NULL
 * colList : List of ColumnDef; It contains explicitly given column's
 *           security context.
 * createAs : True, if SELECT INTO creates this new table.
 */
DatumPtr
sepgsql_relation_create(const char *relName,
						char relkind,
						TupleDesc tupDesc,
						Oid nspOid,
						Node *relLabel,
						List *colList,
						bool createAs)
{
	ListCell   *l;
	Datum	   *result;
	char	   *tcontext;
	char	   *ccontext;
	uint32		permissions;
	int			index;

	if (!sepgsql_is_enabled())
		return NULL;

	/*
	 * check db_schema:{add_name} permission.
	 * It adds a new name entry to the given schema, independent from
	 * relkind of the relation.
	 * Note that we don't need to check this permission on creation of
	 * TOAST table, but no code path given RELKIND_TOASTVALUE now.
	 */
	sepgsql_schema_common(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);

	/*
	 * No need to check anymore expect for regular tables
	 */
	if (relkind != RELKIND_RELATION)
		return NULL;

	/*
	 * check db_table:{create (insert)} permission on the new table
	 */
	if (!relLabel)
		tcontext = sepgsql_default_table_context(nspOid);
	else
	{
		Assert(IsA(relLabel, String));

		tcontext = sepgsql_mcstrans_in(strVal(relLabel));
		if (security_check_context_raw(tcontext) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
					 errmsg("invalid security context \"%s\"", tcontext)));
	}

	permissions = SEPG_DB_TABLE__CREATE;
	/*
	 * SELECT INTO also appends new entries to contents of the new table,
	 * not only creation of the metadata, so we need to check permission
	 * db_table:{insert} which controls to append any data into contents.
	 */
	if (createAs)
		permissions |= SEPG_DB_TABLE__INSERT;

	sepgsql_compute_perms(sepgsql_get_client_context(),
						  tcontext,
						  SEPG_CLASS_DB_TABLE, permissions,
						  relName, true);
	/*
	 * The result array contains security contexts to be assigned on
	 * the new table and columns. The result[0] stores the security
	 * context of the table.
	 * And, result[attnum - FirstLowInvalidHeapAttributeNumber] stores
	 * the security context of the column with this attribute number.
	 */
	result = palloc0(sizeof(Datum) * (tupDesc->natts
					 - FirstLowInvalidHeapAttributeNumber));

	result[0] = PointerGetDatum(makeString(tcontext));

	/*
	 * check db_column:{create (insert)} permission on the new columns
	 */
	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < tupDesc->natts;
		 index++)
	{
		Form_pg_attribute	attr;
		char		audit_name[NAMEDATALEN * 2 + 3];

		/* skip unnecessary attribute */
		if (index == ObjectIdAttributeNumber && !tupDesc->tdhasoid)
			continue;

		if (index < 0)
			attr = SystemAttributeDefinition(index, tupDesc->tdhasoid);
		else
			attr = tupDesc->attrs[index];

		/*
		 * Is there any explicit given security context or copied one
		 * on the inherited column from the parent relation?
		 * If exist, SE-PgSQL applies it instead of the default context.
		 * Otherwise, it computes a default security context to be assigned
		 * on the new column.
		 * Note that we cannot use sepgsql_default_column_context() here,
		 * because the table owning the column is not still constructed.
		 */
		ccontext = NULL;

		foreach (l, colList)
		{
			ColumnDef  *cdef = lfirst(l);

			if (cdef->secontext &&
				strcmp(cdef->colname, NameStr(attr->attname)) == 0)
			{
				Assert(IsA(cdef->secontext, String));

				ccontext = sepgsql_mcstrans_in(strVal(cdef->secontext));
				if (security_check_context_raw(ccontext) < 0)
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
							 errmsg("invalid security context \"%s\"",
									ccontext)));
				break;
			}
		}
		if (!ccontext)
			ccontext = sepgsql_compute_create(sepgsql_get_client_context(),
											  tcontext,
											  SEPG_CLASS_DB_COLUMN);
		/*
		 * Check permission to create a new column, and to append any
		 * value on the column, if necessary.
		 */
		permissions = SEPG_DB_COLUMN__CREATE;
		if (createAs && index >= 0)
			permissions |= SEPG_DB_COLUMN__INSERT;

		snprintf(audit_name, sizeof(audit_name), "%s.%s",
				 relName, NameStr(attr->attname));
		sepgsql_compute_perms(sepgsql_get_client_context(),
							  ccontext,
							  SEPG_CLASS_DB_COLUMN, permissions,
							  audit_name, true);

		/* column's security context to be assigned */
		result[index - FirstLowInvalidHeapAttributeNumber]
			= PointerGetDatum(makeString(ccontext));
	}

	return result;
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
	if (!sepgsql_is_enabled())
		return;

	sepgsql_relation_common(relOid, SEPG_DB_TABLE__SETATTR, true);

	/*
	 * If ALTER TABLE with RENAME TO, we consider it as adding/removing
	 * an entry to/from the current schema concurrently.
	 */
	if (newName)
	{
		sepgsql_schema_common(get_rel_namespace(relOid),
							  SEPG_DB_SCHEMA__ADD_NAME |
							  SEPG_DB_SCHEMA__REMOVE_NAME, true);
	}

	/*
	 * If ALTER TABLE with SET SCHEMA, we considers it as removing
	 * an entry from the current schema and adding an entry to the
	 * new schema concurrently.
	 */
	if (OidIsValid(newNsp))
	{
		sepgsql_schema_common(get_rel_namespace(relOid),
							  SEPG_DB_SCHEMA__REMOVE_NAME, true);
		sepgsql_schema_common(newNsp, SEPG_DB_SCHEMA__ADD_NAME, true);
	}
}

/*
 * sepgsql_relation_drop
 *
 * It checks client's privilege to drop a certain relation and columns
 * owned by the relation. If violated, it raises an error.
 *
 * This hook should be called when user's query tries to drop a cerain
 * table, including cascaded deletions, not only DROP TABLE statement.
 *
 * It checks db_table:{drop} permission, if the given relation is a
 * regular table (RELKIND_RELATION). Otherwise, it does not apply any
 * checks.
 *
 * relOid : OID of the relation to be dropped
 */
void
sepgsql_relation_drop(Oid relOid)
{
	if (!sepgsql_is_enabled())
		return;

	/*
	 * If the relation is a regular table, we scan pg_attribute to
	 * pick up corresponding columns, and check db_column:{ drop }
	 * permission.
	 */
	if (get_rel_relkind(relOid) == RELKIND_RELATION)
	{
		Relation	rel;
		SysScanDesc	scan;
		ScanKeyData	key[1];
		HeapTuple	tuple;

		rel = heap_open(AttributeRelationId, AccessShareLock);

		ScanKeyInit(&key[0],
					Anum_pg_attribute_attrelid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(relOid));

		scan = systable_beginscan(rel, AttributeRelidNumIndexId, true,
								  SnapshotNow, 1, key);

		while (HeapTupleIsValid(tuple = systable_getnext(scan)))
		{
			Form_pg_attribute	attForm
				= (Form_pg_attribute) GETSTRUCT(tuple);

			/* column is already dropped? */
			if (attForm->attisdropped)
				continue;

			sepgsql_attribute_drop(relOid, attForm->attnum);
		}
		systable_endscan(scan);
		heap_close(rel, AccessShareLock);
	}

	/*
	 * Also, check db_table:{drop} permission needless to say
	 */
	sepgsql_relation_common(relOid, SEPG_DB_TABLE__DROP, true);
}

/*
 * sepgsql_relation_grant
 *
 * It checks client's privilege to grant/revoke permissions on a certain
 * relation. If violated, it raises an error.
 *
 * This hook should be called on the routine to handle GRANT/REVOKE
 * on the relations. It also modifies metadata of the relation, so we
 * need to check db_table:{setattr} permission on a pair of the client
 * and the table.
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
Value *
sepgsql_relation_relabel(Oid relOid, Node *relLabel)
{
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled")));

	Assert(IsA(relLabel, String));

	context = sepgsql_mcstrans_in(strVal(relLabel));
	if (security_check_context_raw(context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("invalid security context \"%s\"", context)));

	/* check db_table:{setattr relabelfrom} on the older context */
	sepgsql_relation_common(relOid,
							SEPG_DB_TABLE__SETATTR |
							SEPG_DB_TABLE__RELABELFROM, true);

	/* check db_table:{relabelto} on the newer context */
	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_TABLE,
						  SEPG_DB_TABLE__RELABELTO,
						  get_rel_name(relOid), true);

	return makeString(context);
}

/*
 * sepgsql_relation_truncate
 *
 * It checks client's privilege to truncate contents of the given table.
 * If violated, it raises an error.
 *
 * This hook should be called on truncate_check_rel() which also checks
 * permission in the default PG model. Since this operation dropps all
 * the contents in the table, so we need to check db_table:{delete}
 * permission.
 *
 * rel : Relation object to be truncated
 */
void
sepgsql_relation_truncate(Relation rel)
{
	if (!sepgsql_is_enabled())
		return;

	sepgsql_relation_common(RelationGetRelid(rel),
							SEPG_DB_TABLE__DELETE, true);
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

/*
 * sepgsql_attribute_common
 *
 * A helper function to check required permissions on a pair of the client
 * and the given column.
 */
bool
sepgsql_attribute_common(Oid relOid, AttrNumber attnum,
						 uint32 required, bool abort)
{
	Form_pg_attribute	attForm;
	HeapTuple	tuple;
	Datum		datum;
	bool		rc, isnull;
	char		audit_name[NAMEDATALEN * 2 + 3];
	char	   *context = NULL;

	/*
	 * No need to check any more, if given attribute is not
	 * owned by regular relation
	 */
	if (get_rel_relkind(relOid) != RELKIND_RELATION)
		return true;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relOid),
						   Int16GetDatum(attnum),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for attribute %d of relation %u",
			 attnum, relOid);

	datum = SysCacheGetAttr(ATTNUM, tuple,
							Anum_pg_attribute_attsecon, &isnull);
	if (!isnull)
		context = TextDatumGetCString(datum);
	/*
	 * If the attribute does not have any valid security context,
	 * we uses system's "unlabeled" context as a fallback.
	 */
	if (!context || security_check_context_raw(context) < 0)
		context = sepgsql_get_unlabeled_context();

	attForm = (Form_pg_attribute) GETSTRUCT(tuple);
	snprintf(audit_name, sizeof(audit_name), "%s.%s",
			 get_rel_name(relOid), NameStr(attForm->attname));
	rc = sepgsql_compute_perms(sepgsql_get_client_context(),
							   context,
							   SEPG_CLASS_DB_COLUMN,
							   required, 
							   audit_name, abort);
	ReleaseSysCache(tuple);

	return rc;
}

/*
 * sepgsql_attribute_create
 *
 * It checks permission to create a new column, and returns a security
 * context to be assigned on. If violated, it raises an error.
 *
 * Note that we don't expect to invoke this hook on CREATE TABLE,
 * because default security context of columns are computed based on
 * a pair of client and parent table, but the parent table is not
 * visible when we create a new table.
 * (These checks are done in sepgsql_relation_create().)
 * It intends to be invoked on ALTER TABLE with ADD COLUMN option.
 *
 * If the table has inherited children, ALTER TABLE tries to create
 * a new column on the child tables also. In this case, the caller
 * must copy the security context on the root column to inherited
 * columns, so we never compute a default context twice or more.
 *
 * relOid : OID of the relation which shall own the new column
 * cdef   : ColumnDef object of the new column
 */
Value *
sepgsql_attribute_create(Oid relOid, ColumnDef *cdef)
{
	char	audit_name[NAMEDATALEN * 2 + 3];
	char   *context;
	char	relkind;

	if (!sepgsql_is_enabled())
		return NULL;

	/*
	 * If the relation is not a regular table, no need to check
	 * anything, and no need to assign an individual security
	 * context on the new attribute.
	 */
	relkind = get_rel_relkind(relOid);
	if (relkind != RELKIND_RELATION)
	{
		if (cdef->secontext)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("Only regular column can have its own "
							"security context")));

		return NULL;
	}

	/*
	 * Either a default security context or an explicit security
	 * context shall be assigned on the new column.
	 *
	 * If the new column is an inherited one from the parent,
	 * it must have an identical security context. In this case,
	 * cdef->secontext is already set up on the invocation for
	 * the creation of parent's column. So, we don't need to
	 * compute a default security context again.
	 */
	if (!cdef->secontext)
	{
		Assert(cdef->is_local);

		context = sepgsql_default_column_context(relOid);
	}
	else
	{
		Assert(IsA(cdef->secontext, String));

		context = sepgsql_mcstrans_in(strVal(cdef->secontext));
		if (security_check_context_raw(context) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
					 errmsg("invalid security context \"%s\"", context)));
	}

	snprintf(audit_name, sizeof(audit_name), "%s.%s",
			 get_rel_name(relOid), cdef->colname);
	sepgsql_compute_perms(sepgsql_get_client_context(),
						  context,
						  SEPG_CLASS_DB_COLUMN,
						  SEPG_DB_COLUMN__CREATE,
						  audit_name, true);
	/*
	 * The checked security context should be returned to caller.
	 * Caller has to assign it on the new column.
	 */
	return makeString(context);
}

/*
 * sepgsql_attribute_alter
 *
 * It checks permission to alter properties of the given column.
 * If violated, it raises an error.
 *
 * relOid  : OID of the relation owning the column
 * attname : Name of the column to be altered
 */
void
sepgsql_attribute_alter(Oid relOid, const char *attname)
{
	char		relkind;
	AttrNumber	attnum;

	if (!sepgsql_is_enabled())
		return;

	/*
	 * If user specified non-exist attribute to be dropped,
	 * the caller raises error later, so we don't need to do here.
	 */
	attnum = get_attnum(relOid, attname);
	if (attnum == InvalidAttrNumber)
		return;

	/*
	 * SE-PgSQL only checks permission to drop individual columns
	 * only when it is owned by regular table (=RELKIND_RELATION).
	 */
	relkind = get_rel_relkind(relOid);
	if (relkind == RELKIND_RELATION)
		sepgsql_attribute_common(relOid, attnum,
								 SEPG_DB_COLUMN__SETATTR, true);
}

/*
 * sepgsql_attribute_drop
 *
 * It checks permission to drop the given column. 
 * If violated, it raises an error.
 *
 * In fact, ALTER TABLE with DROP COLUMN does not delete a certain
 * entry of pg_attribute. (It just set pg_attribute.attisdropped.)
 * But it seems to a deletion from user's perspective, so we checks
 * permission to drop a certain column, and do nothing when the table
 * will be dropped.
 *
 * relOid  : OID of the relation owning the column
 * attnum  : Attribute number of the column to be dropped
 */
void
sepgsql_attribute_drop(Oid relOid, AttrNumber attnum)
{
	char		relkind;

	if (!sepgsql_is_enabled())
		return;

	/*
	 * SE-PgSQL only checks permission to drop individual columns
	 * only when it is owned by regular table (=RELKIND_RELATION).
	 */
	relkind = get_rel_relkind(relOid);
	if (relkind != RELKIND_RELATION)
		return;

	sepgsql_attribute_common(relOid, attnum,
							 SEPG_DB_COLUMN__DROP, true);
}

/*
 * sepgsql_attribute_grant
 *
 * It checks permission to grant/revoke permission on a certain column.
 * If violated, it raises an error.
 *
 * From the perspective of SE-PgSQL, ACLs are one of the properties in
 * columns. So, we need to check db_column:{setattr} permission here.
 *
 * relOid : OID of the relation owning the column
 * attnum : Attribute number of the column to be granted/revoked
 */
void
sepgsql_attribute_grant(Oid relOid, AttrNumber attnum)
{
	char	relkind;

	if (!sepgsql_is_enabled())
		return;

	relkind = get_rel_relkind(relOid);
	if (relkind != RELKIND_RELATION)
		return;

	sepgsql_attribute_common(relOid, attnum,
							 SEPG_DB_COLUMN__SETATTR, true);
}

/*
 * sepgsql_attribute_relabel
 *
 * It checks permission to relabel a certain column.
 * If violated, it raises an error.
 *
 * Security context is a special property from the perspective of SE-PgSQL.
 * So, it needs to check two more permissions for this, not only
 * db_column:{setattr} which is a permission to alter property of columns.
 *
 * If the table has inherited children, it needs to relabel inherited
 * columns also with same security context. In this case, the caller
 * has to copy the security context on the root column to inherited
 * columns, but no need to invoke this hook on the children.
 *
 * relOid   : OID of the relation owning the column
 * attname  : Name of the column to be relabeled
 * attLabel : An explicit security context to be assigned on
 */
Value *
sepgsql_attribute_relabel(Oid relOid, const char *attname, Node *attLabel)
{
	char	audit_name[NAMEDATALEN * 2 + 3];
	char   *context;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SE-PostgreSQL is disabled")));

	Assert(IsA(attLabel, String));

	context = sepgsql_mcstrans_in(strVal(attLabel));
	if (security_check_context_raw(context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("invalid security context \"%s\"", context)));

	/* check db_column:{setattr relabelfrom} on the older context */
	sepgsql_attribute_common(relOid, get_attnum(relOid, attname),
							 SEPG_DB_COLUMN__SETATTR |
							 SEPG_DB_COLUMN__RELABELFROM, true);

	/* check db_column:{relabelto} on the newer context */
	snprintf(audit_name, sizeof(audit_name), "%s.%s",
			 get_rel_name(relOid), attname);
	sepgsql_compute_perms(sepgsql_get_client_context(),
                          context,
						  SEPG_CLASS_DB_COLUMN,
						  SEPG_DB_COLUMN__RELABELTO,
						  audit_name, true);

	return makeString(context);
}

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
 * a part of properties of the database object being commented.
 * So, we checks db_xxx:{setattr} permission (it controls modification
 * of the metadata) on a pair of the client and the database object to
 * be commented on.
 *
 * This hook should be called from CreateComments() or CreateSharedComments().
 * When client tries to comment on the managed object, it checks appropriate
 * permission.
 *
 * relOid : OID of the system catalog which stores the database object
 * objId  : OID of the database object itself, to be commented on.
 * subId  : attribute number of the column, if relOid is AttributeRelationId.
 */
void
sepgsql_object_comment(Oid relOid, Oid objId, int32 subId)
{
	if (!sepgsql_is_enabled())
		return;

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
			sepgsql_attribute_common(objId, subId,
									 SEPG_DB_TABLE__SETATTR, true);
		break;

	default:
		/* do nothing */
		break;
	}
}

/*
 * sepgsql_object_drop
 *
 * It checks client's privilege to drop a certain database objects
 * also including ones to be dropped due to cascaded deletion.
 * We assume this hook is invoked from routines in catalog/dependency.c.
 *
 * However, here is some exception cases.
 * If a certain quite internal stuff tries to clean up database objects,
 * we don't apply any checks on the operations, because it is not requests
 * from the client.
 * In the current version, we don't check db_xxx:{drop} permission in the
 * following cases:
 *
 * - cleaning up temporary objects on connection closed.
 *   (RemoveTempRelations)
 * - cleaning up temporary table on relation rebuild.
 *   (rebuild_relation and ATRewriteTables)
 * - cleaning up temporary table due to the ON COMMIT DROP
 *   (PreCommit_on_commit_actions)
 * - cleaning up an orphan temporary table by autovacuum
 *   (do_autovacuum)
 *
 * object : A reference to the database object to be dropped
 */
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
			sepgsql_attribute_drop(object->objectId, object->objectSubId);
		break;

	case OCLASS_SCHEMA:
		sepgsql_schema_drop(object->objectId);
		break;

	case OCLASS_DATABASE:	/* should not be happen */
	default:
		/* do nothing */
		break;
	}
}
