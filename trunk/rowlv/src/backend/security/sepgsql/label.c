/*
 * src/backend/utils/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/xact.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

/*
 * sepgsqlTupleDescHasSecLabel
 *   controls TupleDesc->tdhasseclabel
 */
bool sepostgresql_row_level;

bool
sepgsqlTupleDescHasSecLabel(Relation rel)
{
	if (!sepgsqlIsEnabled())
		return false;

	if (rel != NULL &&
		RelationGetForm(rel)->relkind != RELKIND_RELATION)
		return false;

	if (rel != NULL &&
		(RelationGetRelid(rel) == DatabaseRelationId ||		/* for db_database class */
		 RelationGetRelid(rel) == RelationRelationId ||		/* for db_table class */
		 RelationGetRelid(rel) == AttributeRelationId ||	/* for db_column class */
		 RelationGetRelid(rel) == ProcedureRelationId))		/* for db_procedure class */
		return true;

	return sepostgresql_row_level;	/* db_tuple class depends on a GUC parameter */
}

/*
 * sepgsqlMetaSecurityLabel
 *   returns a security context of tuples within pg_security
 */
char *
sepgsqlMetaSecurityLabel(void)
{
	security_context_t	tcontext;
	sepgsql_sid_t		tsid;
	HeapTuple			tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(SecurityRelationId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u",
			 SecurityRelationId);

	tsid = HeapTupleGetSecLabel(tuple);

	ReleaseSysCache(tuple);

	tcontext = securityLookupSecurityLabel(tsid);
	if (!tcontext || !sepgsqlCheckValidSecurityLabel(tcontext))
		tcontext = sepgsqlGetUnlabeledLabel();

	return sepgsqlComputeCreate(sepgsqlGetServerLabel(),
								tcontext, SECCLASS_DB_TUPLE);
}

/*
 * sepgsqlInputGivenSecLabel
 *   translate a given security label in text form into a security
 *   identifier. It can raise an error, if its format is violated,
 *   but permission checks are done later.
 */
sepgsql_sid_t
sepgsqlInputGivenSecLabel(DefElem *defel)
{
	security_context_t context;

	if (!defel)
		return PointerGetDatum(NULL);

	if (!sepgsqlIsEnabled())
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: disabled now")));

	context = sepgsqlSecurityLabelTransIn(strVal(defel->arg));

	if (!sepgsqlCheckValidSecurityLabel(context))
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: \"%s\" is not a valid security context", context)));

	return securityLookupSecurityId(context);
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
sepgsqlSecurityLabelTransIn(security_context_t context)
{
	security_context_t raw_context, result;

	if (selinux_trans_to_raw_context(context, &raw_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate external label: %s", context)));
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
 * sepgsqlSecurityLabelTransOut()
 *   translate internal security label into external one
 */
security_context_t
sepgsqlSecurityLabelTransOut(security_context_t context)
{
	security_context_t trans_context, result;

	if (selinux_raw_to_trans_context(context, &trans_context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not translate internal label: %s", context)));
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

/*
 * sepgsqlCheckValidSecurityLabel()
 *   checks whether the given security context is a valid one, or not
 */
bool
sepgsqlCheckValidSecurityLabel(security_context_t context)
{
	if (security_check_context_raw(context) < 0)
		return false;

	return true;
}
