/*
 * src/backend/security/sepgsql/label.c
 * 
 * Routines to manage security context
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_security_label.h"

/* GUC option to turn on/off mcstrans feature */
bool	sepostgresql_mcstrans;




/*
 * sepgsql_bootstrap_labeling
 *
 *
 *
 *
 */
void
sepgsql_bootstrap_labeling(Relation rel, Datum *values, bool *nulls)
{
	static char	   *defcon_database = NULL;
	static char	   *defcon_schema = NULL;
	static char	   *defcon_table = NULL;
	static char	   *defcon_column = NULL;
	Oid				attrelid;

	if (!sepgsql_is_enabled())
		return;

	/*
	 *
	 *
	 *
	 *
	 */
	if (!defcon_database)
	{
		MemoryContext	oldctx;
		char		   *dir_context;

		if (getfilecon_raw(DataDir, &dir_context) < 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not get security context: %m")));

		oldctx = MemoryContextSwitchTo(TopMemoryContext);

		defcon_database = sepgsql_compute_create(sepgsql_get_client_context(),
												 dir_context,
												 SEPG_CLASS_DB_DATABASE);
		defcon_schema = sepgsql_compute_create(sepgsql_get_client_context(),
											   defcon_database,
											   SEPG_CLASS_DB_SCHEMA);
		defcon_table = sepgsql_compute_create(sepgsql_get_client_context(),
											  defcon_schema,
											  SEPG_CLASS_DB_TABLE);
		defcon_column = sepgsql_compute_create(sepgsql_get_client_context(),
											   defcon_table,
											   SEPG_CLASS_DB_COLUMN);
		MemoryContextSwitchTo(oldctx);

		freecon(dir_context);
	}

	switch (RelationGetRelid(rel))
	{
	case DatabaseRelationId:
		values[Anum_pg_database_datsecon - 1]
			= CStringGetTextDatum(defcon_database);
		nulls[Anum_pg_database_datsecon - 1] = false;
		break;

	case NamespaceRelationId:
		values[Anum_pg_namespace_nspsecon - 1]
			= CStringGetTextDatum(defcon_schema);
		nulls[Anum_pg_namespace_nspsecon - 1] = false;
		break;

	case RelationRelationId:
		/*
		 * db_table class should be only applied when relkind equals to
		 * RELKIND_RELATION. We assume only regular tables are inserted
		 * to pg_class catalog using InsertOneTuple(), so here is no
		 * checks for relkind.
		 */
		values[Anum_pg_class_relsecon - 1]
			= CStringGetTextDatum(defcon_table);
		nulls[Anum_pg_class_relsecon - 1] = false;
		break;

	case AttributeRelationId:
		/*
		 * In same reason, we don't check relkind of the relation
		 * referenced by attrelid.
		 */
		values[Anum_pg_attribute_attsecon - 1]
			= CStringGetTextDatum(defcon_column);
		nulls[Anum_pg_attribute_attsecon - 1] = false;
		break;

	default:
		/*
		 * No need to set default security context
		 */
	}
}


/*
 * sepgsql_mcstrans_in
 *
 *
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
 *
 *
 *
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
