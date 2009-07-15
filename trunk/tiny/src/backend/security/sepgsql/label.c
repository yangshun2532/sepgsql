/*
 * src/backend/security/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "storage/fd.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"

/* GUC parameter to turn on/off mcstrans */
bool sepostgresql_mcstrans;

/*
 * sepgsqlSetDefaultSecLabel
 *
 * It shall be called from InsertOneTuple() on the BootstrapingMode
 * to assign a default security label.
 */
void
sepgsqlSetDefaultSecLabel(Relation rel, Datum *values, bool *nulls)
{
	char   *seclabel;

	/*
	 * postgresql.bki tries to set _null_ on the security label.
	 */
	if (!sepgsqlIsEnabled())
		return;

	switch (RelationGetRelid(rel))
	{
	case DatabaseRelationId:
		seclabel = sepgsqlGetDefaultDatabaseSecLabel();
		values[Anum_pg_database_datseclabel - 1]
			= CStringGetTextDatum(seclabel);
		nulls[Anum_pg_database_datseclabel - 1] = false;
		break;

	case NamespaceRelationId:
		/*
		 * we assume no temporary namespaces are not initialize
		 * during bootstraping mode.
		 */
		seclabel = sepgsqlGetDefaultSchemaSecLabel(MyDatabaseId);
		values[Anum_pg_namespace_nspseclabel - 1]
			= CStringGetTextDatum(seclabel);
		nulls[Anum_pg_namespace_nspseclabel - 1] = false;
		break;

	case ProcedureRelationId:
		seclabel = sepgsqlGetDefaultProcedureSecLabel(PG_CATALOG_NAMESPACE);
		values[Anum_pg_proc_proseclabel - 1]
			= CStringGetTextDatum(seclabel);
		nulls[Anum_pg_proc_proseclabel - 1] = false;
		break;

	default:
		/* do nothing */
		break;
	}
}

/*
 * sepgsqlGetDefaultDatabaseSecLabel
 *
 * It returns a default security label of db_database object.
 */
char *
sepgsqlGetDefaultDatabaseSecLabel(void)
{
	char	buffer[MAXPGPATH];
	char   *seclabel;
	char   *policy_type;
	char   *tmp;
	FILE   *filp;

	/*
	 * NOTE: When the security policy provides a configuration
	 * file to describe the default security label of database
	 * object, SE-PgSQL uses it as the default.
	 * (TODO: move a routine to read the file into libselinux)
	 *
	 * If the configuration is unavailable, it computes the
	 * default security label without any parant objects.
	 */
	if (selinux_getpolicytype(&policy_type) < 0)
		goto fallback;

	snprintf(buffer, sizeof(buffer),
			 "%s%s/contexts/sepgsql_context",
			 selinux_path(), policy_type);

	filp = AllocateFile(buffer, PG_BINARY_R);
	if (!filp)
		goto fallback;

	while (fgets(buffer, sizeof(buffer), filp) != NULL)
	{
		tmp = strchr(buffer, '#');
		if (tmp)
			*tmp = '\0';

		seclabel = strtok(buffer, " \t\n\r");
		if (!seclabel)
			continue;

		/* An entry found */
		FreeFile(filp);
		return sepgsqlTransSecLabelIn(seclabel);
	}
	FreeFile(filp);

fallback:
	return sepgsqlComputeCreate(sepgsqlGetClientLabel(),
								sepgsqlGetClientLabel(),
								SEPG_CLASS_DB_DATABASE);
}

/*
 * defaultSecLabelWithDatabase
 *
 * A helper function which returns a default security label
 * of the new object being created under a certain schema
 */
static char *
defaultSecLabelWithDatabase(Oid relid, Oid database_oid, uint16 tclass)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *datseclabel;

	if (IsBootstrapProcessingMode())
	{
		static char *cached = NULL;
		/*
		 * On the initdb processes, we may not able to refer
		 * database using system caches. An assumption is
		 * nobody relabels during the bootstraping mode.
		 * So, we assume the database always has its default
		 * security label in this mode.
		 */
		if (!cached)
		{
			char   *temp = sepgsqlGetDefaultDatabaseSecLabel();

			cached = MemoryContextStrdup(TopMemoryContext, temp);
		}
		datseclabel = cached;
	}
	else
	{
		/* Fetch pg_database.datseclabel */
		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(database_oid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for database: %u", database_oid);

		datum = SysCacheGetAttr(DATABASEOID, tuple,
								Anum_pg_database_datseclabel, &isnull);
		if (isnull)
			datseclabel = sepgsqlRawSecLabelOut(NULL);
		else
			datseclabel = sepgsqlRawSecLabelOut(TextDatumGetCString(datum));

		ReleaseSysCache(tuple);
	}

	/*
	 * The security policy can suggest a default security label to
	 * the combination of subject-label (client process), target-
	 * label (database object which owns the new object) and 
	 * object class.
	 */
	return sepgsqlClientCreateLabel(datseclabel, tclass);
}

/*
 * sepgsqlGetDefaultSchemaSecLabel
 *
 * It returns a default security label of db_schema object.
 */
char *
sepgsqlGetDefaultSchemaSecLabel(Oid database_oid)
{
	return defaultSecLabelWithDatabase(NamespaceRelationId,
									   database_oid,
									   SEPG_CLASS_DB_SCHEMA);
}

/*
 * sepgsqlGetDefaultSchemaTempSecLabel
 *
 * It returns a default security label of db_schema_temp object.
 */
char *
sepgsqlGetDefaultSchemaTempSecLabel(Oid database_oid)
{
	return defaultSecLabelWithDatabase(NamespaceRelationId,
									   database_oid,
									   SEPG_CLASS_DB_SCHEMA_TEMP);
}

/*
 * defaultSecLabelWithSchema
 *
 * A helper function which returns a default security label
 * of the new object being created under a certain schema
 */
static char *
defaultSecLabelWithSchema(Oid relid, Oid namespace_oid, uint16 tclass)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *nspseclabel;

	if (IsBootstrapProcessingMode())
	{
		static char *cached = NULL;

		if (!cached)
		{
			char   *temp = sepgsqlGetDefaultSchemaSecLabel(MyDatabaseId);

			cached = MemoryContextStrdup(TopMemoryContext, temp);
		}
		nspseclabel = cached;
	}
	else
    {
		/* Fetch pg_namespace.nspseclabel */
		tuple = SearchSysCache(NAMESPACEOID,
							   ObjectIdGetDatum(namespace_oid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for namespace: %u", namespace_oid);

		datum = SysCacheGetAttr(NAMESPACEOID, tuple,
								Anum_pg_namespace_nspseclabel, &isnull);
		if (isnull)
			nspseclabel = sepgsqlRawSecLabelOut(NULL);
		else
			nspseclabel = sepgsqlRawSecLabelOut(TextDatumGetCString(datum));

		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreateLabel(nspseclabel, tclass);
}

/*
 * sepgsqlGetDefaultProcedureSecLabel
 *
 * It returns a default security label of db_procedure object.
 */
char *
sepgsqlGetDefaultProcedureSecLabel(Oid namespace_oid)
{
	return defaultSecLabelWithSchema(ProcedureRelationId,
									 namespace_oid,
									 SEPG_CLASS_DB_PROCEDURE);
}

/*
 * sepgsqlGivenSecLabelIn
 *
 *
 */
Datum
sepgsqlGivenSecLabelIn(DefElem *new_label)
{
	char   *seclabel;

	if (!sepgsqlIsEnabled())
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return PointerGetDatum(NULL);
	}

	if (!new_label)
		return PointerGetDatum(NULL);

	Assert(strcmp(new_label->defname, "security_label") == 0);

	seclabel = sepgsqlTransSecLabelIn(strVal(new_label->arg));

	return CStringGetTextDatum(seclabel);
}

/*
 * sepgsqlAssignDatabaseSecLabel
 *
 * When user gives an explicit security label using SECURITY LABEL option,
 * it applies sanity checks on the given label. Otherwise, it computes
 * a default security label on the new database object, and returns it.
 * 
 * Anyway, it returns a valid security label to be assigned on the new
 * database object, when SE-PgSQL is available. Otherwise, it returns
 * NULL, and createdb() set NULL on the pg_database.seclabel.
 * It means the new database does not have any certain security label.
 * If we enables SE-PgSQL later, it checks user's permission to the
 * "unlabeled" security label provided by system, when user tries to
 * to access the unlabeled database.
 */
Datum
sepgsqlAssignDatabaseSecLabel(const char *datname, DefElem *new_label)
{
	char   *deflabel;

	/*
	 * If SE-PgSQL is not enabled, it does not assign any security
	 * label. NULL shall be set, and it is dealt as unlabeled object.
	 */
	if (!sepgsqlIsEnabled())
		return PointerGetDatum(NULL);

	/*
	 * If user provide a security label using SECURITY LABEL option,
	 * it shall be assigned rather than the default security label.
	 */
	if (new_label)
		return sepgsqlGivenSecLabelIn(new_label);

	/*
	 * Otherwise, it assigns the default security label.
	 */
	deflabel = sepgsqlGetDefaultDatabaseSecLabel();

	return CStringGetTextDatum(deflabel);
}

/*
 * sepgsqlAssignSchemaSecLabel
 *
 * When user gives an explicit security label using SECURITY LABEL option,
 * it applies sanity checks on the given label. Otherwise, it computes
 * a default security label on the new namespace object, and returns it.
 *
 * See the comments in sepgsqlAssignDatabaseSecLabel also.
 */
Datum
sepgsqlAssignSchemaSecLabel(const char *nspname, Oid database_oid,
							DefElem *new_label, bool is_temp)
{
	char   *deflabel;

	if (!sepgsqlIsEnabled())
		return PointerGetDatum(NULL);

	if (new_label)
		return sepgsqlGivenSecLabelIn(new_label);

	if (!is_temp)
		deflabel = sepgsqlGetDefaultSchemaSecLabel(database_oid);
	else
		deflabel = sepgsqlGetDefaultSchemaTempSecLabel(database_oid);

	return CStringGetTextDatum(deflabel);
}

/*
 * sepgsqlAssignProcedureSecLabel
 *
 * When user gives an explicit security label using SECURITY LABEL option,
 * it applies sanity checks on the given label. Otherwise, it computes
 * a default security label on the new procedure object, and returns it.
 *
 * See the comments in sepgsqlAssignDatabaseSecLabel also.
 */
Datum
sepgsqlAssignProcedureSecLabel(const char *proname, Oid namespace_oid,
							   DefElem *new_label)
{
	char   *deflabel;

	if (!sepgsqlIsEnabled())
		return PointerGetDatum(NULL);

	if (new_label)
		return sepgsqlGivenSecLabelIn(new_label);

	deflabel = sepgsqlGetDefaultProcedureSecLabel(namespace_oid);

	return CStringGetTextDatum(deflabel);
}

/*
 * sepgsqlTransSecLabelIn
 *
 * It translate the given security label from user readable format
 * to raw format, if sepostgresql_mcstrans is turned on. Then, it
 * also delivers the label to sepgsqlRawSecLabelIn().
 */
char *
sepgsqlTransSecLabelIn(char *seclabel)
{
	security_context_t	temp;

	if (sepgsqlIsEnabled() && sepostgresql_mcstrans)
	{
		if (selinux_trans_to_raw_context(seclabel, &temp) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: failed to translate \"%s\"", seclabel)));
		PG_TRY();
		{
			seclabel = pstrdup(temp);
		}
		PG_CATCH();
		{
			freecon(temp);
			PG_RE_THROW();
		}
		PG_END_TRY();
		freecon(temp);
	}
	return sepgsqlRawSecLabelIn(seclabel);
}

/*
 * sepgsqlTransSecLabelOut
 *
 * It delivers the given security label to sepgsqlRawSecLabelOut(),
 * and translates it from raw format to human readable format.
 */
char *
sepgsqlTransSecLabelOut(char *seclabel)
{
	security_context_t	temp;

	seclabel = sepgsqlRawSecLabelOut(seclabel);

	if (sepgsqlIsEnabled() && sepostgresql_mcstrans)
	{
		if (selinux_raw_to_trans_context(seclabel, &temp) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: failed to translate \"%s\"", seclabel)));
		PG_TRY();
		{
			seclabel = pstrdup(temp);
		}
		PG_CATCH();
		{
			freecon(temp);
			PG_RE_THROW();
		}
		PG_END_TRY();
		freecon(temp);
	}
	return seclabel;
}

/*
 * sepgsqlRawSecLabelIn
 *
 * It applies sanity check to the given security context.
 * If it it not valid format, it raises an error.
 */
char *
sepgsqlRawSecLabelIn(char *seclabel)
{
	if (sepgsqlIsEnabled())
	{
		if (!seclabel || security_check_context_raw(seclabel) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("Invalid security context: \"%s\"", seclabel)));
	}
	return seclabel;
}

/*
 * sepgsqlRawSecLabelOut
 *
 * It applies sanity check to the given security context.
 * If it is not valid format, it returns unlabeled context instead.
 */
char *
sepgsqlRawSecLabelOut(char *seclabel)
{
	if (sepgsqlIsEnabled())
	{
		if (!seclabel || security_check_context_raw(seclabel) < 0)
		{
			security_context_t	unlabeled_con;

			if (security_get_initial_context_raw("unlabeled",
												 &unlabeled_con) < 0)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("Unabled to get unlabeled security context")));
			PG_TRY();
			{
				seclabel = pstrdup(unlabeled_con);
			}
			PG_CATCH();
			{
				freecon(unlabeled_con);
				PG_RE_THROW();
			}
			PG_END_TRY();
			freecon(unlabeled_con);
		}
	}
	return seclabel;
}
