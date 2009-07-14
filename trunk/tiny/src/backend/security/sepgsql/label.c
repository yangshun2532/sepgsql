/*
 * src/backend/security/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "security/sepgsql.h"

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
	char *seclabel;

	switch (RelationGetRelid(rel))
	{
	case DatabaseRelationId:
		break;

	case NamespaceRelationId:
		break;

	case ProcedureRelationId:
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

	snprintf(buffer, sizeof(filename),
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
		return securityTransSecLabelIn(DatabaseRelationId, seclabel);
	}
	FreeFile(filp);

fallback:
	seclabel = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
									sepgsqlGetClientLabel(),
									SEPG_CLASS_DB_DATABASE);
	return sepgsqlTransSecLabelIn(DatabaseRelationId, seclabel);
}

/*
 * defaultSecLabelWithDatabase
 *
 * A helper function which returns a default security label
 * of the new object being created under a certain schema
 */
static char *
defaultSecLabelWithSchema(Oid relid, Oid database_oid, uint16 tclass)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *datseclabel;

	if (IsBootstrapProcessingMode())
	{
		static char *cached = NULL;

		if (!cached)
		{
			char   *temp = sepgsqlGetDefaultDatabaseSecLabel();

			cached = MemoryContextStrdup(TopMemoryContext, temp);
		}
		datseclabel = cached;
	}
	else
	{
		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(database_oid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for database: %u", datoid);

		datum = SysCacheGetAttr(DATABASEOID, tuple,
								Anum_pg_database_datseclabel, &isnull);
		if (isnull)
			datseclabel = sepgsqlRawSecLabelOut(DatabaseRelationId, NULL);
		else
			datseclabel = sepgsqlRawSecLabelOut(DatabaseRelationId,
												TextDatumGetCString(datum));
	}

	return sepgsqlClientCreateSecLabel(DatabaseRelationId, datseclabel,
									   tclass, relid);
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
		tuple = SearchSysCache(NAMESPACEOID,
							   ObjectIdGetDatum(namespace_oid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for namespace: %u", namespace_oid);

		datum = SysCacheGetAttr(NAMESPACEOID, tuple,
								Anum_pg_namespace_nspseclabel, &isnull);
		if (isnull)
			datseclabel = sepgsqlRawSecLabelOut(NamespaceRelationId, NULL);
		else
			datseclabel = sepgsqlRawSecLabelOut(NamespaceRelationId,
												TextDatumGetCString(datum));
	}

	return sepgsqlClientCreateSecLabel(NamespaceRelationId, datseclabel,
									   tclass, relid);
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
		PG_TRY()
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
			PG_TYR();
			{
				seclabel = pstrdup(unlabeledcon);
			}
			PG_CATCH();
			{
				freecon(unlabeledcon);
				PG_RE_THROW();
			}
			PG_END_TRY();
			freecon(unlabeledcon);
		}
	}
	return seclabel;
}
