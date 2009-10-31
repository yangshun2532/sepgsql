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
 * sepgsql_get_client_context
 *
 *
 *
 */
static char *client_context = NULL;

char *
sepgsql_get_client_context(void)
{
	if (!client_context)
	{
		/*
		 * When this server provess was launched with single-user mode,
		 * it does not have any client socket, and the server process also
		 * performs as a client. So, we apply server's security context as
		 * a client's one.
		 * The getcon_raw(3) is an API of SELinux to obtain the security
		 * context of the current process in raw format.
		 */
		if (!MyProcPort)
		{
			if (getcon_raw(&client_context) < 0)
				ereport(ERROR,
						(errcode(ERRCODE_INTERNAL_ERROR),
						 errmsg("SELinux: could not get server context")));

			return client_context;
		}

		/*
		 * Otherwise, SE-PgSQL obtains the security context of the client
		 * process using getpeercon(3). It is an API of SELinux to obtain
		 * the security context of the peer process for the given file
		 * descriptor of the client socket.
		 * If MyProcPort->sock came from unix domain socket, we don't need
		 * any special configuration. If it is tcp/ip socket, either labeled
		 * ipsec or static fallback context should be configured.
		 */
		if (getpeercon_raw(MyProcPort->sock, &client_context) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("SELinux: could not get client context")));
	}
	return client_context;
}

/*
 * sepgsql_get_unlabeled_context
 *
 *
 *
 *
 */
static char *unlabeled_context = NULL;

char *
sepgsql_get_unlabeled_context(void)
{
	if (!unlabeled_context)
	{
		if (security_get_initial_context_raw("unlabeled",
											 &unlabeledcon) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("SELinux: could not get 'unlabeled' context")));
	}
	return unlabeled_context;
}

/*
 * sepgsql_get_database_context 
 *
 * It returns the pg_database.datsecon as a cstring, or NULL.
 */
char *
sepgsql_get_database_context(Oid datOid)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *result = NULL;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		datum = SysCacheGetAttr(DATABASEOID, tuple,
								Anum_pg_database_datsecon, &isnull);
		if (!isnull)
			result = TextDatumGetCString(datum);

		ReleaseSysCache(tuple);
	}
	return result;
}

/*
 * sepgsql_get_namespace_context
 *
 * It returns pg_namespace.nspsecon as a plain cstring, or NULL.
 */
char *
sepgsql_get_namespace_context(Oid nspOid)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *result = NULL;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nspOid),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		datum = SysCacheGetAttr(NAMESPACEOID,
								Anum_pg_namespace_nspsecon, &isnull);
		if (!isnull)
			result = TextDatumGetCString(datum);

		ReleaseSysCache(tuple);
	}
	return result;
}

/*
 * sepgsql_get_relation_context
 *
 * It returns pg_class.relsecon as a plain cstring, or NULL.
 */
char *
sepgsql_get_relation_context(Oid relOid)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *result = NULL;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relOid),
						   0, 0, 0);
	if (HeapTupleIsValid(tuple))
	{
		datum = SysCacheGetAttr(RELOID,
								Anum_pg_class_relsecon, &isnull);
		if (!isnull)
			result = TextDatumGetCString(datum);

		ReleaseSysCache(tuple);
	}
	return result;
}

/*
 * sepgsql_get_attribute_context
 *
 * It returns pg_attribute.attsecon as a plain cstring, or NULL.
 */
char *
sepgsql_get_attribute_context(Oid relOid, AttrNumber attnum)
{
	HeapTuple	tuple;
	Datum		datum;
	bool		isnull;
	char	   *result = NULL;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relOid),
						   Int16GetDatum(attnum),
						   0, 0);
	if (HeapTupleIsValid(tuple))
	{
		datum = SysCacheGetAttr(ATTNUM,
								Anum_pg_attribute_attsecon, &isnull);
		if (!isnull)
			result = TextDatumGetCString(datum);

		ReleaseSysCache(tuple);
	}
	return result;
}

/*
 *
 *
 *
 *
 *
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
