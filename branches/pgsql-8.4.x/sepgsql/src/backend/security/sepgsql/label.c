/*
 * src/backend/security/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/heap.h"
#include "catalog/indexing.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/sepgsql.h"
#include "storage/fd.h"
#include "utils/syscache.h"

/* GUC: to turn on/off row level controls in SE-PostgreSQL */
bool sepostgresql_row_level;

/* GUC parameter to turn on/off mcstrans */
bool sepostgresql_use_mcstrans;

/*
 * sepgsqlTupleDescHasSecLabel
 *
 *   returns a hint whether we should allocate a field to store
 *   security label on the given relation, or not.
 */
bool
sepgsqlTupleDescHasSecLabel(Oid relid, char relkind)
{
	if (!sepgsqlIsEnabled())
		return false;

	if (!OidIsValid(relid))
		return sepostgresql_row_level;	/* Target of SELECT INTO */

	if (relid == DatabaseRelationId  ||
		relid == NamespaceRelationId ||
		relid == RelationRelationId  ||
		relid == AttributeRelationId ||
		relid == ProcedureRelationId)
		return true;

	return sepostgresql_row_level;
}

/*
 * sepgsqlMetaSecurityLabel
 *   It returns a security label of tuples within pg_security system
 *   catalog. The purpose of this special handling is to avoid infinite
 *   function invocations to insert new entry for meta security labels.
 */
security_context_t
sepgsqlMetaSecurityLabel(void)
{
	HeapTuple			tuple;
	security_context_t	tcontext;
	Oid					tblsid;

	if (!sepgsqlIsEnabled())
		return NULL;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SecurityRelationId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation: \"pg_security\"");

	tblsid = HeapTupleGetSecid(tuple);
	tcontext = securityRawSecLabelOut(RelationRelationId, tblsid);

	ReleaseSysCache(tuple);

	return sepgsqlComputeCreate(sepgsqlGetServerLabel(),
								tcontext, SEPG_CLASS_DB_TUPLE);
}

/*
 * sepgsqlGetDefaultDatabaseSecLabel
 *   It returns the default security label of a database object.
 */
Oid
sepgsqlGetDefaultDatabaseSecLabel(void)
{
	security_context_t	seclabel;
	char		filename[MAXPGPATH];
	char		buffer[1024], *policy_type, *tmp;
	FILE	   *filp;

	/*
	 * NOTE: when the security policy provide a configuration to
	 * specify the default security context of database object,
	 * we apply is as a default one.
	 * If the configuration is unavailable, we compute the
	 * default security context without any parent object.
	 */
	if (selinux_getpolicytype(&policy_type) < 0)
		goto fallback;

	snprintf(filename, sizeof(filename),
			 "%s%s/contexts/sepgsql_context", selinux_path(), policy_type);
	filp = AllocateFile(filename, PG_BINARY_R);
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
	return securityTransSecLabelIn(DatabaseRelationId, seclabel);
}

static Oid
defaultSecLabelWithDatabase(Oid relid, Oid datoid, security_class_t tclass)
{
	HeapTuple	tuple;
	Oid			datsid;

	if (IsBootstrapProcessingMode())
	{
		static Oid cached = InvalidOid;

		if (!OidIsValid(cached))
			cached = sepgsqlGetDefaultDatabaseSecLabel();
		datsid = cached;
	}
	else
	{
		tuple = SearchSysCache(DATABASEOID,
							   ObjectIdGetDatum(datoid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for database: %u", datoid);
		datsid = HeapTupleGetSecid(tuple);

		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreateSecid(DatabaseRelationId, datsid,
									tclass, relid);
}

Oid
sepgsqlGetDefaultSchemaSecLabel(Oid database_oid)
{
	return defaultSecLabelWithDatabase(NamespaceRelationId,
									   database_oid, SEPG_CLASS_DB_SCHEMA);
}

Oid
sepgsqlGetDefaultSchemaTempSecLabel(Oid database_oid)
{
	return defaultSecLabelWithDatabase(NamespaceRelationId,
									   database_oid, SEPG_CLASS_DB_SCHEMA_TEMP);
}

static Oid
defaultSecLabelWithSchema(Oid relid, Oid nspoid, security_class_t tclass)
{
	HeapTuple	tuple;
	Oid			nspsid;

	if (IsBootstrapProcessingMode())
	{
		static Oid cached  = InvalidOid;

		if (!OidIsValid(cached))
			cached = sepgsqlGetDefaultSchemaSecLabel(MyDatabaseId);
		nspsid = cached;
	}
	else
	{
		tuple = SearchSysCache(NAMESPACEOID,
							   ObjectIdGetDatum(nspoid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for namespace: %u", nspoid);

		nspsid = HeapTupleGetSecid(tuple);

		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreateSecid(NamespaceRelationId, nspsid,
									tclass, relid);
}

Oid
sepgsqlGetDefaultTableSecLabel(Oid namespace_oid)
{
	return defaultSecLabelWithSchema(RelationRelationId,
									 namespace_oid,
									 SEPG_CLASS_DB_TABLE);
}

Oid
sepgsqlGetDefaultSequenceSecLabel(Oid namespace_oid)
{
	return defaultSecLabelWithSchema(RelationRelationId,
									 namespace_oid,
									 SEPG_CLASS_DB_SEQUENCE);
}

Oid
sepgsqlGetDefaultProcedureSecLabel(Oid namespace_oid)
{
	return defaultSecLabelWithSchema(ProcedureRelationId,
									 namespace_oid,
									 SEPG_CLASS_DB_PROCEDURE);
}

static Oid
defaultSecLabelWithTable(Oid relid, Oid tbloid, security_class_t tclass)
{
	HeapTuple	tuple;
	Oid			tblsid;

	if (IsBootstrapProcessingMode()
		&& (tbloid == TypeRelationId ||
			tbloid == ProcedureRelationId ||
			tbloid == AttributeRelationId ||
			tbloid == RelationRelationId))
	{
		static Oid cached = InvalidOid;

		if (!OidIsValid(cached))
			cached = sepgsqlGetDefaultTableSecLabel(PG_CATALOG_NAMESPACE);
		tblsid = cached;
	}
	else
	{
		tuple = SearchSysCache(RELOID,
							   ObjectIdGetDatum(tbloid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for relation: %u", tbloid);

		tblsid = HeapTupleGetSecid(tuple);

		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreateSecid(RelationRelationId, tblsid,
									tclass, relid);
}

Oid
sepgsqlGetDefaultColumnSecLabel(Oid table_oid)
{
	return defaultSecLabelWithTable(AttributeRelationId,
									table_oid,
									SEPG_CLASS_DB_COLUMN);
}

Oid
sepgsqlGetDefaultTupleSecLabel(Oid table_oid)
{
	return defaultSecLabelWithTable(table_oid,
									table_oid,
									SEPG_CLASS_DB_TUPLE);
}

Oid
sepgsqlGetDefaultBlobSecLabel(Oid database_oid)
{
	return defaultSecLabelWithDatabase(LargeObjectRelationId,
									   MyDatabaseId,
									   SEPG_CLASS_DB_BLOB);
}

void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple)
{
	Oid		relid = RelationGetRelid(rel);
	Oid		newsid, nspoid, tbloid;

	if (!sepgsqlIsEnabled())
		return;

	if (!HeapTupleHasSecid(tuple))
		return;

	switch (sepgsqlTupleObjectClass(relid, tuple))
	{
	case SEPG_CLASS_DB_DATABASE:
		newsid = sepgsqlGetDefaultDatabaseSecLabel();
		break;
	case SEPG_CLASS_DB_SCHEMA:
		newsid = sepgsqlGetDefaultSchemaSecLabel(MyDatabaseId);
		break;
	case SEPG_CLASS_DB_SCHEMA_TEMP:
		newsid = sepgsqlGetDefaultSchemaTempSecLabel(MyDatabaseId);
		break;
	case SEPG_CLASS_DB_TABLE:
		nspoid = ((Form_pg_class) GETSTRUCT(tuple))->relnamespace;
		newsid = sepgsqlGetDefaultTableSecLabel(nspoid);
		break;
	case SEPG_CLASS_DB_SEQUENCE:
		nspoid = ((Form_pg_class) GETSTRUCT(tuple))->relnamespace;
		newsid = sepgsqlGetDefaultSequenceSecLabel(nspoid);
		break;
	case SEPG_CLASS_DB_PROCEDURE:
		nspoid = ((Form_pg_proc) GETSTRUCT(tuple))->pronamespace;
		newsid = sepgsqlGetDefaultProcedureSecLabel(nspoid);
		break;
	case SEPG_CLASS_DB_COLUMN:
		tbloid = ((Form_pg_attribute) GETSTRUCT(tuple))->attrelid;
		newsid = sepgsqlGetDefaultColumnSecLabel(tbloid);
		break;
	case SEPG_CLASS_DB_BLOB:
		newsid = sepgsqlGetDefaultBlobSecLabel(MyDatabaseId);
		break;
	default:
		newsid = sepgsqlGetDefaultTupleSecLabel(relid);
		break;
	}

	HeapTupleSetSecid(tuple, newsid);
}

/*
 * sepgsqlCreateTableColumn
 *   It returns an array of security identifier for the new table
 *   and columns to be assigned. The corresponding security labels
 *   are already checked for db_table/db_sequence/db_column:{create}
 *   permission.
 *   In the default labeling rule, a column inherits the security
 *   label of its table, but we cannot refer it using system caches,
 *   because the command counter is not incremented under the
 *   heap_create_with_catalog(). Thus, we need to compute and check
 *   them prior to the actual creation of table and columns.
 */
Oid *
sepgsqlCreateTableColumns(CreateStmt *stmt,
						  const char *relname, Oid namespace_oid,
						  TupleDesc tupdesc, char relkind)
{
	Oid	   *secLabels = NULL;
	Oid		relsid = InvalidOid;
	int		index;

	if (!sepgsqlIsEnabled())
		return NULL;

	/*
	 * In the current version, we don't assign any certain security
	 * labels on relations except for tables/sequences.
	 */
	if (relkind != RELKIND_RELATION && relkind != RELKIND_SEQUENCE)
		return NULL;

	/*
	 * The secLabels array stores security identifiers to be assigned
	 * on the new table and columns.
	 * 
	 * secLabels[0] is security identifier of the table.
	 * secLabels[attnum - FirstLowInvalidHeapAttributeNumber]
	 *   is security identifier of columns.
	 */
	secLabels = palloc0(sizeof(Oid) * (tupdesc->natts
							- FirstLowInvalidHeapAttributeNumber));

	/*
	 * SELinux checks db_table/db_sequence:{create}
	 */
	switch (relkind)
	{
	case RELKIND_RELATION:
		if (!stmt || !stmt->secLabel)
			relsid = sepgsqlGetDefaultTableSecLabel(namespace_oid);
		else
			relsid = securityTransSecLabelIn(RelationRelationId,
								strVal(((DefElem *)stmt->secLabel)->arg));
		sepgsqlClientHasPermsSid(RelationRelationId, relsid,
								 SEPG_CLASS_DB_TABLE,
								 SEPG_DB_TABLE__CREATE,
								 relname, true);
		break;

	case RELKIND_SEQUENCE:
		if (!stmt || !stmt->secLabel)
			relsid = sepgsqlGetDefaultSequenceSecLabel(namespace_oid);
		else
			relsid = securityTransSecLabelIn(RelationRelationId,
								strVal(((DefElem *)stmt->secLabel)->arg));
		sepgsqlClientHasPermsSid(RelationRelationId, relsid,
								 SEPG_CLASS_DB_SEQUENCE,
								 SEPG_DB_SEQUENCE__CREATE,
								 relname, true);
		break;

	default:
		if (stmt && stmt->secLabel)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("Unable to set security label on \"%s\"", relname)));
		relsid = sepgsqlGetDefaultTupleSecLabel(RelationRelationId);
		break;
	}
	/* table's security identifier to be assigned on */
	secLabels[0] = relsid;

	/*
	 * SELinux checks db_column:{create}
	 */
	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < tupdesc->natts;
		 index++)
	{
		Form_pg_attribute	attr;
		char	attname[NAMEDATALEN * 2 + 3];
		Oid		attsid = InvalidOid;

		/* skip unnecessary attributes */
		if (index < 0 && (relkind == RELKIND_VIEW ||
						  relkind == RELKIND_COMPOSITE_TYPE))
			continue;
		if (index == ObjectIdAttributeNumber && !tupdesc->tdhasoid)
			continue;

		if (index < 0)
			attr = SystemAttributeDefinition(index, tupdesc->tdhasoid);
		else
			attr = tupdesc->attrs[index];

		/* Is there any given security label? */
		if (stmt)
		{
			ListCell   *l;

			foreach (l, stmt->tableElts)
			{
				ColumnDef  *colDef = lfirst(l);

				if (colDef->secLabel &&
					strcmp(colDef->colname, NameStr(attr->attname)) == 0)
				{
					attsid = securityTransSecLabelIn(AttributeRelationId,
									strVal(((DefElem *)colDef->secLabel)->arg));
					break;
				}
			}
		}

		switch (relkind)
		{
		case RELKIND_RELATION:
			/* compute default column's label if necessary */
			if (!OidIsValid(attsid))
				attsid = sepgsqlClientCreateSecid(RelationRelationId, relsid,
												  SEPG_CLASS_DB_COLUMN,
												  AttributeRelationId);

			sprintf(attname, "%s.%s", relname, NameStr(attr->attname));
			sepgsqlClientHasPermsSid(AttributeRelationId, attsid,
									 SEPG_CLASS_DB_COLUMN,
									 SEPG_DB_COLUMN__CREATE,
									 attname, true);
			break;

		default:
			if (OidIsValid(attsid))
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("Unable to set security label on \"%s.%s\"",
								relname, NameStr(attr->attname))));
			attsid = sepgsqlGetDefaultTupleSecLabel(AttributeRelationId);
			break;
		}
		/* column's security identifier to be assigend on */
		secLabels[index - FirstLowInvalidHeapAttributeNumber] = attsid;
	}
	return secLabels;
}

/*
 * sepgsqlCopyTableColumns
 *   It returns an array of security identifier of table and columns
 *   to be copied on make_new_heap(). It actually create a new temporary
 *   relation and insert all the tuples within original one into the
 *   temporary one, but swap_relation_files() swaps their file nodes.
 *   Thus, there are no changes from the viewpoint of users.
 *   SE-PostgreSQL also does not check and change anything. It simply
 *   copies security identifier of the source relation to the destination
 *   relation.
 */
Oid *
sepgsqlCopyTableColumns(Relation source)
{
	HeapTuple	tuple;
	Oid		   *secLabels;
	Oid			relid = RelationGetRelid(source);
	int			index;

	if (!sepgsqlIsEnabled())
		return PointerGetDatum(NULL);

	/* see the comment at sepgsqlCreateTableColumn*/
	secLabels = palloc0(sizeof(Oid) * (RelationGetDescr(source)->natts
							- FirstLowInvalidHeapAttributeNumber));

	/* copy table's security identifier */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation \"%s\"",
			 RelationGetRelationName(source));

	secLabels[0] = HeapTupleGetSecid(tuple);

	ReleaseSysCache(tuple);

	/* copy column's security identifier */
	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < RelationGetDescr(source)->natts;
		 index++)
	{
		Form_pg_attribute	attr;

		if (index < 0)
			attr = SystemAttributeDefinition(index, true);
		else
			attr = RelationGetDescr(source)->attrs[index];

		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(relid),
							   Int16GetDatum(attr->attnum),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			continue;

		secLabels[index - FirstLowInvalidHeapAttributeNumber]
			= HeapTupleGetSecid(tuple);

		ReleaseSysCache(tuple);
	}

	return secLabels;
}

/*
 * sepgsqlRawSecLabelIn
 *   correctness checks for the given security context
 */
char *
sepgsqlRawSecLabelIn(char *seclabel)
{
	if (!sepgsqlIsEnabled())
		return seclabel;

	if (!seclabel || security_check_context_raw(seclabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("Invalid security context: \"%s\"", seclabel)));

	return seclabel;
}

/*
 * sepgsqlRawSecLabelOut
 *   correctness checks for the given security context,
 *   and replace it if invalid security context
 */
char *
sepgsqlRawSecLabelOut(char *seclabel)
{
	if (!sepgsqlIsEnabled())
		return seclabel;

	if (!seclabel || security_check_context_raw(seclabel) < 0)
	{
		security_context_t	unlabeledcon;

		if (security_get_initial_context_raw("unlabeled",
											 &unlabeledcon) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("Unabled to get unlabeled security context")));
		PG_TRY();
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
	return seclabel;
}

/*
 * sepgsqlTransSecLabelIn
 * sepgsqlTransSecLabelOut
 *   translation between human-readable and raw format
 */
char *
sepgsqlTransSecLabelIn(char *seclabel)
{
	security_context_t	rawlabel;
	security_context_t	result;

	if (!sepgsqlIsEnabled() ||
		!sepostgresql_use_mcstrans)
		return seclabel;

	if (selinux_trans_to_raw_context(seclabel, &rawlabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: failed to translate \"%s\"", seclabel)));
	PG_TRY();
	{
		result = pstrdup(rawlabel);
	}
	PG_CATCH();
	{
		freecon(rawlabel);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(rawlabel);

	return result;
}

char *
sepgsqlTransSecLabelOut(char *seclabel)
{
	security_context_t	translabel;
	security_context_t	result;

	if (!sepgsqlIsEnabled() ||
		!sepostgresql_use_mcstrans)
		return seclabel;

	if (selinux_raw_to_trans_context(seclabel, &translabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: failed to translate \"%s\"", seclabel)));
	PG_TRY();
	{
		result = pstrdup(translabel);
	}
	PG_CATCH();
	{
		freecon(translabel);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(translabel);

	return result;
}
