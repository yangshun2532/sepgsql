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
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

/* GUC: to turn on/off row level controls in SE-PostgreSQL */
bool sepostgresql_row_level;

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
		return false;	/* target of SELECT INTO */

	if (RelationGetRelid(rel) == DatabaseRelationId  ||
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
extern void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple)
{
	security_class_t	tclass;
	security_context_t	context;
	Form_pg_attribute	attForm;
	HeapTuple			reltup;
	Oid					newsid, table_sid;

	Assert(HeapTupleHasSecLabel(tuple));
	tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);

	switch (tclass)
	{
	case SEPG_CLASS_DB_DATABASE:
		context = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
									   sepgsqlGetClientLabel(),
									   SEPG_CLASS_DB_DATABASE);
		newsid = securityLookupSecurityId(context);
		break;

	case SEPG_CLASS_DB_TABLE:
		newsid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
									 SEPG_CLASS_DB_TABLE);
		break;

	case SEPG_CLASS_DB_PROCEDURE:
		newsid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
									 SEPG_CLASS_DB_PROCEDURE);
		break;

	case SEPG_CLASS_DB_COLUMN:
		attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		if (IsBootstrapProcessingMode() &&
			(attForm->attrelid == TypeRelationId ||
			 attForm->attrelid == ProcedureRelationId ||
			 attForm->attrelid == AttributeRelationId ||
			 attForm->attrelid == RelationRelationId))
		{
			table_sid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
											SEPG_CLASS_DB_TABLE);
		}
		else
		{
			reltup = SearchSysCache(RELOID,
									ObjectIdGetDatum(attForm->attrelid),
									0, 0, 0);
			if (!HeapTupleIsValid(reltup))
				elog(ERROR, "SELinux: cache lookup failed fro relation: %u",
					 attForm->attrelid);
			
			table_sid = HeapTupleGetSecLabel(reltup);
			ReleaseSysCache(reltup);
		}
		newsid = sepgsqlClientCreate(table_sid, SEPG_CLASS_DB_COLUMN);
		break;

	default:	/* SEPG_CLASS_DB_TUPLE */
		if (IsBootstrapProcessingMode() &&
			(RelationGetRelid(rel) == TypeRelationId ||
			 RelationGetRelid(rel) == ProcedureRelationId ||
			 RelationGetRelid(rel) == AttributeRelationId ||
			 RelationGetRelid(rel) == RelationRelationId))
		{
			table_sid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
											SEPG_CLASS_DB_TABLE);
		}
		else
		{
			reltup = SearchSysCache(RELOID,
									ObjectIdGetDatum(RelationGetRelid(rel)),
									0, 0, 0);
			if (!HeapTupleIsValid(reltup))
				elog(ERROR, "SELinux: cache lookup failed fro relation: %u",
					 RelationGetRelid(rel));
			table_sid = HeapTupleGetSecLabel(reltup);
			ReleaseSysCache(reltup);
		}
		newsid = sepgsqlClientCreate(table_sid, SEPG_CLASS_DB_TUPLE);
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
				 errmsg("SELinux: not a valid security context: \"%s\"",
						context)));

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

	if (selinux_trans_to_raw_context(seclabel, &rawlabel) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: failed to translate \"%s\" to raw format",
						seclabel)));
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

	if (selinux_raw_to_trans_context(rawlabel, &seclabel) < 0)
		ereport(ERROR,
                (errcode(ERRCODE_SELINUX_ERROR),
                 errmsg("SELinux: failed to translate \"%s\" to readable format",
                        rawlabel)));
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
