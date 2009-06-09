/*
 * src/backend/security/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/xact.h"
#include "catalog/catalog.h"
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
#include "utils/builtins.h"
#include "utils/memutils.h"
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
sepgsqlTupleDescHasSecLabel(Relation rel)
{
	if (!sepgsqlIsEnabled())
		return false;

	if (rel == NULL)
		return sepostgresql_row_level;	/* target of SELECT INTO */

	if (RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return false;

	if (RelationGetRelid(rel) == DatabaseRelationId  ||
		RelationGetRelid(rel) == NamespaceRelationId ||
		RelationGetRelid(rel) == RelationRelationId  ||
		RelationGetRelid(rel) == AttributeRelationId ||
		RelationGetRelid(rel) == ProcedureRelationId)
		return true;

	return sepostgresql_row_level;
}

/*
 * sepgsqlSetDefaultSecLabel 
 *
 *   assigns a default security context for the newly inserted tuple.
 */
static Oid
defaultDatabaseSecLabel(void)
{
	security_context_t context;
	char		filename[MAXPGPATH];
	char		buffer[512], *ptype, *tmp;
	FILE	   *filp;

	/*
	 * NOTE: A special handling is necessary to determine the default
	 * label for db_database obejct class because it does not have
	 * its parent object, so we cannot apply normal type transition
	 * here. At first, it tries to fetch the default context from the
	 * configuration file of selinux-policy. If it is invalid, we 
	 * determine it based on only the context of client (compatible
	 * behavior).
	 */
	if (selinux_getpolicytype(&ptype) < 0)
		goto fallback;

	snprintf(filename, sizeof(filename),
			 "%s%s/contexts/sepgsql_context", selinux_path(), ptype);
	filp = AllocateFile(filename, PG_BINARY_R);
	if (!filp)
		goto fallback;

	while (fgets(buffer, sizeof(buffer), filp) != NULL)
	{
		tmp = strchr(buffer, '#');
		if (tmp)
			*tmp = '\0';

		context = strtok(buffer, " \t\n\r");
		if (!context)
			continue;

		/* An entry found */
		FreeFile(filp);
		return securityLookupSecurityId(context);
	}
	FreeFile(filp);

fallback:
	context = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
								   sepgsqlGetClientLabel(),
								   SEPG_CLASS_DB_DATABASE);
	return securityLookupSecurityId(context);
}

static Oid
defaultSchemaSecLabelCommon(security_class_t tclass)
{
	HeapTuple	tuple;
	Oid			newsid;

	if (IsBootstrapProcessingMode())
	{
		static Oid cached = InvalidOid;

		if (!OidIsValid(cached))
			cached = sepgsqlClientCreate(defaultDatabaseSecLabel(), tclass);

		return cached;
	}

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", MyDatabaseId);

	newsid = sepgsqlClientCreate(HeapTupleGetSecLabel(tuple), tclass);

	ReleaseSysCache(tuple);

	return newsid;


}

static Oid
defaultSchemaSecLabel(void)
{
	return defaultSchemaSecLabelCommon(SEPG_CLASS_DB_SCHEMA);
}

static Oid
defaultSchemaTempSecLabel(void)
{
	return defaultSchemaSecLabelCommon(SEPG_CLASS_DB_SCHEMA_TEMP);
}

static Oid
defaultSecLabelWithSchema(Oid nspoid, security_class_t tclass)
{
	HeapTuple	tuple;
	Oid			newsid;

	if (IsBootstrapProcessingMode())
	{
		static Oid cached  = InvalidOid;

		if (!OidIsValid(cached))
			cached = defaultSchemaSecLabel();

		return sepgsqlClientCreate(cached, tclass);
	}

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nspoid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace: %u", nspoid);

	newsid = sepgsqlClientCreate(HeapTupleGetSecLabel(tuple), tclass);

	ReleaseSysCache(tuple);

	return newsid;
}

static Oid
defaultTableSecLabel(Oid nspoid)
{
	return defaultSecLabelWithSchema(nspoid, SEPG_CLASS_DB_TABLE);
}

static Oid
defaultSequenceSecLabel(Oid nspoid)
{
	return defaultSecLabelWithSchema(nspoid, SEPG_CLASS_DB_SEQUENCE);
}

static Oid
defaultProcedureSecLabel(Oid nspoid)
{
	return defaultSecLabelWithSchema(nspoid, SEPG_CLASS_DB_PROCEDURE);
}

static Oid
defaultSecLabelWithTable(Oid relid, security_class_t tclass)
{
	HeapTuple	tuple;
	Oid			relsid;

	if (IsBootstrapProcessingMode()
		&& (relid == TypeRelationId ||
			relid == ProcedureRelationId ||
			relid == AttributeRelationId ||
			relid == RelationRelationId))
	{
		static Oid cached = InvalidOid;

		if (!OidIsValid(cached))
			cached = defaultTableSecLabel(PG_CATALOG_NAMESPACE);
		relsid = cached;
	}
	else
	{
		tuple = SearchSysCache(RELOID,
							   ObjectIdGetDatum(relid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for relation: %u", relid);

		relsid = HeapTupleGetSecLabel(tuple);

		ReleaseSysCache(tuple);
	}

	return sepgsqlClientCreate(relsid, tclass);
}

static Oid
defaultColumnSecLabel(Oid relid)
{
	return defaultSecLabelWithTable(relid, SEPG_CLASS_DB_COLUMN);
}

static Oid
defaultTupleSecLabel(Oid relid)
{
	return defaultSecLabelWithTable(relid, SEPG_CLASS_DB_TUPLE);
}

static Oid
defaultBlobSecLabel(void)
{
	/*
	 * NOTE:
	 * A binary largeobject has its characteristic which has
	 * one-to-any relationship between itself and tuples.
	 * In other word, a large object consists of multiple
	 * tuple, and the security context of thr first page
	 * represents whole of the binary largeobject.
	 * It requires all the pages within a single largeobejct
	 * to have identical security context, and the assumption
	 * is kept by a hardwired rule which prevent to manipulate
	 * pg_largeobject system catalog by hand.
	 * 
	 * The security context of the first page is copied to
	 * write new pages, so the default security context is
	 * only asked when we create a new largeobject.
	 */
	HeapTuple	tuple;
	Oid			newsid;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", MyDatabaseId);

	newsid = sepgsqlClientCreate(HeapTupleGetSecLabel(tuple),
								 SEPG_CLASS_DB_BLOB);
	ReleaseSysCache(tuple);

	return newsid;
}

extern void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple)
{
	Form_pg_class		clsForm;
	Form_pg_proc		proForm;
	Form_pg_attribute	attForm;
	Oid		relid = RelationGetRelid(rel);
	Oid		newsid;

	Assert(HeapTupleHasSecLabel(tuple));

	switch (sepgsqlTupleObjectClass(relid, tuple))
	{
	case SEPG_CLASS_DB_DATABASE:
		newsid = defaultDatabaseSecLabel();
		break;

	case SEPG_CLASS_DB_SCHEMA:
		newsid = defaultSchemaSecLabel();
		break;

	case SEPG_CLASS_DB_SCHEMA_TEMP:
		newsid = defaultSchemaTempSecLabel();
		break;

	case SEPG_CLASS_DB_TABLE:
		clsForm = (Form_pg_class) GETSTRUCT(tuple);
		newsid = defaultTableSecLabel(clsForm->relnamespace);
		break;

	case SEPG_CLASS_DB_SEQUENCE:
		clsForm = (Form_pg_class) GETSTRUCT(tuple);
		newsid = defaultSequenceSecLabel(clsForm->relnamespace);
		break;

	case SEPG_CLASS_DB_PROCEDURE:
		proForm = (Form_pg_proc) GETSTRUCT(tuple);
		newsid = defaultProcedureSecLabel(proForm->pronamespace);
		break;

	case SEPG_CLASS_DB_COLUMN:
		attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		newsid = defaultColumnSecLabel(attForm->attrelid);
		break;

	case SEPG_CLASS_DB_BLOB:
		newsid = defaultBlobSecLabel();
		break;

	default: /* SEPG_CLASS_DB_TUPLE */
		newsid = defaultTupleSecLabel(relid);
		break;
	}

	HeapTupleSetSecLabel(tuple, newsid);
}

/*
 * sepgsqlMetaSecurityLabel
 *   It returns a security label of tuples within pg_security system
 *   catalog. The purpose of this special handling is to avoid infinite
 *   function invocations to insert new entry for meta security labels.
 */
char *
sepgsqlMetaSecurityLabel(void)
{
	HeapTuple			tuple;
	security_context_t	tcontext;
	Oid					tsecid;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SecurityRelationId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation: pg_security");

	tsecid = HeapTupleGetSecLabel(tuple);

	ReleaseSysCache(tuple);

	tcontext = securityLookupSecurityLabel(tsecid);
	if (!tcontext || security_check_context(tcontext) < 0)
		tcontext = sepgsqlGetUnlabeledLabel();

	return sepgsqlComputeCreate(sepgsqlGetServerLabel(),
								tcontext,
								SEPG_CLASS_DB_TUPLE);
}

/*
 * sepgsqlInputGivenSecLabel
 *   translate a given security label in text form into a security
 *   identifier. It can raise an error, if its format is violated,
 *   but permission checks are done later.
 */
Oid
sepgsqlInputGivenSecLabel(DefElem *defel)
{
	security_context_t	context;

	if (!defel)
		return InvalidOid;

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	context = strVal(defel->arg);
	if (security_check_context(context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("Not a valid security context: \"%s\"", context)));

	return securityTransSecLabelIn(context);
}

/*
 * sepgsqlInputGivenSecLabelRelation
 *   organize a set of given security labels on CREATE TABLE statement.
 *   User can specify a security label for individual table/columns.
 *   It returns a list of DefElem. !defel->defname means a specified one
 *   for the table, rest of them means one for columns.
 */
List *
sepgsqlInputGivenSecLabelRelation(CreateStmt *stmt)
{
	List	   *results = NIL;
	ListCell   *l;
	DefElem	   *defel, *newel;

	if (stmt->secLabel)
	{
		defel = (DefElem *) stmt->secLabel;

		Assert(IsA(defel, DefElem));

		newel = makeDefElem(NULL, copyObject(defel->arg));
		results = lappend(results, newel);
	}

	foreach (l, stmt->tableElts)
	{
		ColumnDef  *cdef = lfirst(l);

		if (cdef->secLabel)
		{
			defel = (DefElem *) cdef->secLabel;

			Assert(IsA(defel, DefElem));

			newel = makeDefElem(pstrdup(cdef->colname),
								copyObject(defel->arg));
			results = lappend(results, newel);
		}
	}

	return results;
}

/*
 * sepgsqlSecurityLabelTransIn()
 *   translate external security label into internal one
 */
security_context_t
sepgsqlSecurityLabelTransIn(security_context_t seclabel)
{
	security_context_t	rawlabel;
	security_context_t	result;

	if (!sepgsqlIsEnabled())
		return seclabel;

	if (!seclabel || security_check_context(seclabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("Not a valid security context: \"%s\"", seclabel)));

	if (selinux_trans_to_raw_context(seclabel, &rawlabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("Failed to translate \"%s\" to raw format", seclabel)));
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

/*
 * sepgsqlSecurityLabelTransOut()
 *   translate internal security label into external one
 */
security_context_t
sepgsqlSecurityLabelTransOut(security_context_t rawlabel)
{
	security_context_t	seclabel;
	security_context_t	result;

	if (!sepgsqlIsEnabled())
		return rawlabel;

	if (!rawlabel || security_check_context(rawlabel) < 0)
		rawlabel = sepgsqlGetUnlabeledLabel();

	if (!sepostgresql_use_mcstrans)
		return rawlabel;

	if (selinux_raw_to_trans_context(rawlabel, &seclabel) < 0)
		ereport(ERROR,
                (errcode(ERRCODE_SELINUX_ERROR),
                 errmsg("Failed to translate \"%s\" to readable format", rawlabel)));

	PG_TRY();
	{
		result = pstrdup(seclabel);
	}
	PG_CATCH();
	{
		freecon(seclabel);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(seclabel);

	return result;
}
