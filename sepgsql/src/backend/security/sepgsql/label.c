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
 * It replaces the given _null_ in the postgres.bki by the default security
 * context of databases, schemas, tables and columns.
 * This hook has to be called on InsertOneTuple() in bootstrap.c, because
 * we cannot update variable length field in the initdb phase. So, it is
 * necessary to replace values/nulls array prior to the heap_form_tuple().
 *
 * This function replaces the _null_ on the following fields:
 *  - pg_database.datsecon
 *  - pg_namespace.nspsecon
 *  - pg_class.relsecon
 *  - pg_attribute.attsecon
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
	 * We assume all the database objects created in the initdb phase,
	 * so it compute the default security context at onece.
	 * When a default security context is required, it copies a pre-
	 * computed default one to the correct field depending on system
	 * catalog.
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
		break;
	}
}

/*
 * sepgsql_get_client_context
 *
 * It returns the security context of the client process.
 * In most cases, its result will be used as a privilege set of the client.
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
		 * performs as a client in same time.
		 * So, we apply server's security context as a client's one.
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
		 * For example, a process labeled as "system_u:system_r:httpd_t:s0"
		 * (which is typically apache/httpd) connect to the PgSQL server,
		 * getpeercon_raw() in server side returns the security context
		 * in client side.
		 * If MyProcPort->sock came from unix domain socket, we don't need
		 * any special configuration. OS handles them correctly.
		 * If it is tcp/ip socket, either labeled ipsec or static fallback
		 * context should be configured.
		 * The labeled ipsec is a feature to deliver the security context
		 * of remote peer processes with an enhancement of key exchange
		 * server (racoon). If SELinux is also available in the client host
		 * also, it is the most preferable option.
		 * The static fallback context is a feature to assign an alternative
		 * security context based on the source address and network device
		 * in usage. It can be applied, even if Windows is run on the client.
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
