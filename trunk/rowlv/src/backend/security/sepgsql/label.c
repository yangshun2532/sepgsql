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
#include "catalog/pg_shsecurity.h"
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
		return securityTransSecLabelIn(DatabaseRelationId, context);
	}
	FreeFile(filp);

fallback:
	context = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
								   sepgsqlGetClientLabel(),
								   SEPG_CLASS_DB_DATABASE);
	return securityTransSecLabelIn(DatabaseRelationId, context);
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
			cached = defaultDatabaseSecLabel();
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

static Oid
defaultSchemaSecLabel(void)
{
	return defaultSecLabelWithDatabase(NamespaceRelationId,
									   MyDatabaseId,
									   SEPG_CLASS_DB_SCHEMA);
}

static Oid
defaultSchemaTempSecLabel(void)
{
	return defaultSecLabelWithDatabase(NamespaceRelationId,
									   MyDatabaseId,
									   SEPG_CLASS_DB_SCHEMA_TEMP);
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
			cached = defaultSchemaSecLabel();
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

static Oid
defaultTableSecLabel(Oid nspoid)
{
	return defaultSecLabelWithSchema(RelationRelationId,
									 nspoid,
									 SEPG_CLASS_DB_TABLE);
}

static Oid
defaultSequenceSecLabel(Oid nspoid)
{
	return defaultSecLabelWithSchema(RelationRelationId,
									 nspoid,
									 SEPG_CLASS_DB_SEQUENCE);
}

static Oid
defaultProcedureSecLabel(Oid nspoid)
{
	return defaultSecLabelWithSchema(ProcedureRelationId,
									 nspoid,
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
			cached = defaultTableSecLabel(PG_CATALOG_NAMESPACE);
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

static Oid
defaultColumnSecLabel(Oid tbloid)
{
	return defaultSecLabelWithTable(AttributeRelationId,
									tbloid,
									SEPG_CLASS_DB_COLUMN);
}

static Oid
defaultTupleSecLabel(Oid relid)
{
	return defaultSecLabelWithTable(relid,
									relid,
									SEPG_CLASS_DB_TUPLE);
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
sepgsqlMetaSecurityLabel(bool shared)
{
	Oid					secrelid;
	HeapTuple			tuple;
	security_context_t	tcontext;
	Oid					tsecid;

	if (!sepgsqlIsEnabled())
		return NULL;

	secrelid = (shared ? SharedSecurityRelationId : SecurityRelationId);
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(secrelid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation: pg_security");

	tsecid = HeapTupleGetSecLabel(tuple);
	tcontext = securityRawSecLabelOut(RelationRelationId, tsecid);

	ReleaseSysCache(tuple);

	return sepgsqlComputeCreate(sepgsqlGetServerLabel(),
								tcontext,
								SEPG_CLASS_DB_TUPLE);
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

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux is disabled now")));

	return securityTransSecLabelIn(relid, strVal(defel->arg));
}

/*
 * sepgsqlParseCreateStmtSecLabelIn
 *   picks up the given security context using CREATE TABLE and
 *   SECURITY_LABEL enhancement. It returns a DefElem list.
 */
List *
sepgsqlParseCreateStmtSecLabelIn(CreateStmt *stmt)
{
	List	   *results = NIL;
	ListCell   *l;
	DefElem	   *defel;
	Oid			secid;

	if (stmt->secLabel)
	{
		defel = (DefElem *) stmt->secLabel;
		Assert(IsA(defel, DefElem));

		secid = sepgsqlGivenSecLabelIn(RelationRelationId, defel);
		defel = makeDefElem(NULL, makeInteger(secid));
		results = lappend(results, defel);
	}

	foreach (l, stmt->tableElts)
	{
		ColumnDef  *cdef = lfirst(l);

		if (cdef->secLabel)
		{
			defel = (DefElem *) cdef->secLabel;
			Assert(IsA(defel, DefElem));

			secid = sepgsqlGivenSecLabelIn(AttributeRelationId, defel);
			defel = makeDefElem(pstrdup(cdef->colname),
								makeInteger(secid));
			results = lappend(results, defel);
		}
	}

	return results;
}

/*
 * sepgsqlGet/SetMcstransMode
 *   provide an interface to get/set sepostgresql_use_mcstrans
 */
bool
sepgsqlGetMcstransMode(void)
{
	return sepostgresql_use_mcstrans;
}

bool
sepgsqlSetMcstransMode(bool new_mode)
{
	bool	old_mode = sepostgresql_use_mcstrans;

	sepostgresql_use_mcstrans = new_mode;

	return old_mode;
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
