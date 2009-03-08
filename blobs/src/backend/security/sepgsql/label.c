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
#include "catalog/pg_type.h"
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
 * sepgsqlSetDefaultSecLabel
 *
 *   It assigns a default security label on a tuple newly created.
 *   The default security label depends on the security policy, and
 *   its object class.
 *   The db_class and db_tuple class inherits the parent table's one,
 *   but we cannot refer system cache in very early phase, so it assumes
 *   nobody relabels the default one during initdb.
 */
void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple)
{
	Form_pg_attribute	attform;
	security_context_t	context;
	security_class_t	tclass;
	sepgsql_sid_t		newsid, table_sid;
	HeapTuple			reltup;
	const char		   *audit_name;

	Assert(HeapTupleHasSecLabel(tuple));
	tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);

	switch (tclass)
	{
	case SEPG_CLASS_DB_DATABASE:
		context = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
									   sepgsqlGetClientLabel(),
									   SEPG_CLASS_DB_DATABASE);
		newsid = securityTransSecLabelIn(context);
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
		attform = (Form_pg_attribute) GETSTRUCT(tuple);
		if (IsBootstrapProcessingMode() &&
			(attform->attrelid == TypeRelationId ||
			 attform->attrelid == ProcedureRelationId ||
			 attform->attrelid == AttributeRelationId ||
			 attform->attrelid == RelationRelationId))
		{
			table_sid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
											SEPG_CLASS_DB_TABLE);
		}
		else
		{
			reltup = SearchSysCache(RELOID,
									ObjectIdGetDatum(attform->attrelid),
									0, 0, 0);
			if (!HeapTupleIsValid(reltup))
				elog(ERROR, "SELinux: cache lookup failed fro relation: %u",
					 attform->attrelid);

			table_sid = HeapTupleGetSecLabel(reltup);

			ReleaseSysCache(reltup);
		}
		newsid = sepgsqlClientCreate(table_sid, SEPG_CLASS_DB_COLUMN);
		break;

	case SEPG_CLASS_DB_BLOB:
		/*
		 * NOTE:
		 * A object within db_blob class has a characteristic.
		 * It does not have one-to-one mapping on a object and
		 * a tuple, in other word, a large object consists of
		 * multiple tuples. In most cases, user accesses them
		 * via several certain interfaces, like loread().
		 * So, we assume user don't touch pg_largeobject system
		 * catalog by hand, and it does not give us any degradation
		 * at interface incompatibility.
		 * 
		 * Thus, all the tuples modified are come from internal
		 * interfaces, like simple_heap_insert(). The backend
		 * implementation has to set correct security context
		 * prior to insert a tuple. A security context of
		 * largeobject is cached on LargeObjectDesc->secid
		 * The only exception is inv_create(). It invoked
		 * simple_heap_insert() with no security context to
		 * assign a default one here.
		 *
		 * We also check db_blob:{create} permission here,
		 * because only one path come from inv_create()
		 * go through here.
		 */
		newsid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
									 SEPG_CLASS_DB_BLOB);
		audit_name = sepgsqlAuditName(RelationGetRelid(rel), tuple);
		sepgsqlClientHasPerms(newsid,
							  SEPG_CLASS_DB_BLOB,
							  SEPG_DB_BLOB__CREATE,
							  audit_name, true);
		break;

	default:
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
								tcontext,
								SEPG_CLASS_DB_TUPLE);
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
