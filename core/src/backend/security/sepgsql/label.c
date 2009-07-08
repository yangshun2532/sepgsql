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
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/sepgsql.h"
#include "storage/fd.h"
#include "utils/syscache.h"

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
		return false;	/* Target of SELECT INTO */

	if (relid == DatabaseRelationId  ||
		relid == NamespaceRelationId ||
		relid == RelationRelationId  ||
		relid == AttributeRelationId ||
		relid == ProcedureRelationId)
		return true;

	return false;
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
		datsid = HeapTupleGetSecLabel(tuple);

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

		nspsid = HeapTupleGetSecLabel(tuple);

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

		tblsid = HeapTupleGetSecLabel(tuple);

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

void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple)
{
	Oid		relid = RelationGetRelid(rel);
	Oid		newsid, nspoid, tbloid;

	if (!sepgsqlIsEnabled())
		return;

	if (!HeapTupleHasSecLabel(tuple))
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
	default:
		newsid = InvalidOid;
		break;
	}

	HeapTupleSetSecLabel(tuple, newsid);
}

/*
 * sepgsqlCreateTableSecLabels
 *
 */
List *
sepgsqlCreateTableSecLabels(CreateStmt *stmt, Oid namespace_oid, char relkind)
{
	List	   *result = NIL;
	DefElem	   *defel;
	Oid			secid;

	if (!sepgsqlIsEnabled())
		return NIL;

	/*
	 * In the current version, we don't give any security labels
	 * on relations except for tables and sequences.
	 */
	switch (relkind)
	{
	case RELKIND_RELATION:
		secid = sepgsqlGetDefaultTableSecLabel(namespace_oid);
		break;

	case RELKIND_SEQUENCE:
		secid = sepgsqlGetDefaultSequenceSecLabel(namespace_oid);
		break;

	default:
		/* no security labels in this version */
		return NIL;
	}
	defel = makeDefElem(NULL, (Node *) makeInteger(secid));
	result = lappend(result, defel);

	return result;
}

/*
 * sepgsqlCopyTableSecLabels
 *   It returns a list of security identifiers for a new table
 *   which is copied from an existing table.
 *   The make_new_heap() creates a copy of relation, then is
 *   shall be swapped with the original one.
 *   Internally, it creates a new table, but we should not
 *   apply default labeling, because it is not a user visible
 *   change.
 */
List *
sepgsqlCopyTableSecLabels(Relation source)
{
	HeapTuple	tuple;
	Oid			relid = RelationGetRelid(source);
	Oid			secid;
	int			index;
	DefElem	   *defel;
	List	   *result = NIL;

	if (!sepgsqlIsEnabled())
		return NIL;

	/* Copy table's security label */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(relid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation: %u", relid);

	secid = HeapTupleGetSecLabel(tuple);
	defel = makeDefElem(NULL, (Node *)makeInteger(secid));
	result = lappend(result, defel);

	ReleaseSysCache(tuple);

	/* Copy column's security label */
	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < RelationGetDescr(source)->natts;
		 index++)
	{
		Form_pg_attribute	attr;

		if (index < 0)
			attr = SystemAttributeDefinition(index, true);
		else
			attr = RelationGetDescr(source)->attrs[index];

		tuple = SearchSysCacheAttName(relid, NameStr(attr->attname));
		if (!HeapTupleIsValid(tuple))
			continue;

		secid = HeapTupleGetSecLabel(tuple);
		defel = makeDefElem(pstrdup(NameStr(attr->attname)),
							(Node *)makeInteger(secid));
		result = lappend(result, defel);

		ReleaseSysCache(tuple);
	}

	return result;
}

/*
 * sepgsqlGivenSecLabelIn
 *   translate a given security label in text form into a security
 *   identifier. It can raise an error, if its format is violated,
 *   but permission checks are done later.
 */
Oid
sepgsqlGivenSecLabelIn(Oid relid, DefElem *defel)
{
	if (!defel)
		return InvalidOid;

	Assert(IsA(defel, DefElem));

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux is disabled now")));

	return securityTransSecLabelIn(relid, strVal(defel->arg));
}

/*
 * sepgsqlRawSecLabelIn
 *   correctness checks for the given security context
 */
security_context_t
sepgsqlRawSecLabelIn(security_context_t seclabel)
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
security_context_t
sepgsqlRawSecLabelOut(security_context_t seclabel)
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
security_context_t
sepgsqlTransSecLabelIn(security_context_t seclabel)
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

security_context_t
sepgsqlTransSecLabelOut(security_context_t seclabel)
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
