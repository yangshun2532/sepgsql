/*
 * src/backend/utils/sepgsql/label.c
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
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

bool
HeapTupleHasSecLabel(Oid relid, HeapTuple tuple)
{
	security_class_t tclass
		= sepgsqlTupleObjectClass(relid, tuple);

	if (tclass == SECCLASS_DB_DATABASE ||
		tclass == SECCLASS_DB_TABLE ||
		tclass == SECCLASS_DB_COLUMN ||
		tclass == SECCLASS_DB_PROCEDURE)
		return true;

	return false;
}

sepgsql_sid_t
HeapTupleGetSecLabel(Oid relid, HeapTuple tuple)
{
	security_class_t tclass;
	Datum datum;
	bool isnull;

	tclass = sepgsqlTupleObjectClass(relid, tuple);

	switch (tclass)
	{
	case SECCLASS_DB_DATABASE:
		datum = SysCacheGetAttr(DATABASEOID, tuple,
								Anum_pg_database_datselabel,
								&isnull);
		break;

	case SECCLASS_DB_TABLE:
		datum = SysCacheGetAttr(RELOID, tuple,
								Anum_pg_class_relselabel,
								&isnull);
		break;

	case SECCLASS_DB_COLUMN:
		datum = SysCacheGetAttr(ATTNUM, tuple,
								Anum_pg_attribute_attselabel,
								&isnull);
		break;

	case SECCLASS_DB_PROCEDURE:
		datum = SysCacheGetAttr(PROCOID, tuple,
								Anum_pg_proc_proselabel,
								&isnull);
		break;
	default:
		isnull = true;
		break;
	}

	if (isnull)
		return NULL;

	return TextDatumGetCString(datum);
}

/*
 * sepgsqlInputGivenSecLabel
 *   translate a given security label in text form into a security
 *   identifier. It can raise an error, if its format is violated,
 *   but permission checks are done later.
 */
Datum
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

	return CStringGetTextDatum(context);
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
 * sepgsqlSetDefaultSecLabel
 *
 * This function assign a proper security context for a newly inserted tuple,
 * refering the security policy.
 * In the default, any tuple inherits the security context of its table.
 * However, we have several exception for some of system catalog. It come from
 * TYPE_TRANSITION rules in the security policy.
 */
void
sepgsqlSetDefaultSecLabel(Oid relid, Datum *values, bool *nulls, Datum given)
{
	security_context_t ncontext;

	if (!sepgsqlIsEnabled())
		return;

	if (relid == DatabaseRelationId)
	{
		/*
		 * The default security context for db_database class
		 * objects are determinded based on TYPE_TRANSITION
		 * rules on its client's context itself.
		 */
		if (given != PointerGetDatum(NULL))
			values[Anum_pg_database_datselabel - 1] = given;
		else
		{
			ncontext = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
											sepgsqlGetClientLabel(),
											SECCLASS_DB_DATABASE);
			nulls[Anum_pg_database_datselabel - 1] = false;
			values[Anum_pg_database_datselabel - 1]
				= CStringGetTextDatum(ncontext);
		}
		nulls[Anum_pg_database_datselabel - 1] = false;
	}
	else if (relid == RelationRelationId)
	{
		char relkind = DatumGetChar(values[Anum_pg_class_relkind - 1]);

		if (relkind != RELKIND_RELATION)
			nulls[Anum_pg_class_relselabel - 1] = true;
		else
		{
			/*
			 * The default security context for db_table class
			 * objects are determinded based on TYPE_TRANSITION
			 * rules on its database's context.
			 */
			if (given != PointerGetDatum(NULL))
				values[Anum_pg_class_relselabel - 1] = given;
			else
			{
				ncontext = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
											   SECCLASS_DB_TABLE);
				values[Anum_pg_class_relselabel - 1]
					= CStringGetTextDatum(ncontext);
			}
			nulls[Anum_pg_class_relselabel - 1] = false;
		}
	}
	else if (relid == AttributeRelationId)
	{
		char attkind = DatumGetChar(values[Anum_pg_attribute_attkind - 1]);

		if (attkind != RELKIND_RELATION)
			nulls[Anum_pg_attribute_attselabel - 1] = true;
		else
		{
			/*
			 * The default security context for db_database class
			 * objects are determinded based on TYPE_TRANSITION
			 * rules on its table's context.
			 */
			if (given != PointerGetDatum(NULL))
				values[Anum_pg_attribute_attselabel - 1] = given;
			else
			{
				sepgsql_sid_t tblsid;
				Oid attrelid =
					DatumGetObjectId(values[Anum_pg_attribute_attrelid - 1]);

				/*
				 * we assume no one change security context while
				 * bootstraping mode
				 */
				if (IsBootstrapProcessingMode() &&
					(attrelid == TypeRelationId ||
					 attrelid == ProcedureRelationId ||
					 attrelid == AttributeRelationId ||
					 attrelid == RelationRelationId))
				{
					tblsid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
												 SECCLASS_DB_TABLE);
				}
				else
				{
					HeapTuple reltup
						= SearchSysCache(RELOID,
										 ObjectIdGetDatum(attrelid),
										 0, 0, 0);
					if (!HeapTupleIsValid(reltup))
						elog(ERROR, "SELinux: cache lookup failed for relation: %u", attrelid);
					tblsid = HeapTupleGetSecLabel(RelationRelationId, reltup);
					ReleaseSysCache(reltup);
				}
				ncontext = sepgsqlClientCreate(tblsid, SECCLASS_DB_COLUMN);
				values[Anum_pg_attribute_attselabel - 1]
					= CStringGetTextDatum(ncontext);
			}
			nulls[Anum_pg_attribute_attselabel - 1] = false;
		}
	}
	else if (relid == ProcedureRelationId)
	{
		/*
		 * The default security context for db_procedure class
		 * objects are determinded based on TYPE_TRANSITION
		 * rules on its database's context.
		 */
		if (given != PointerGetDatum(NULL))
			values[Anum_pg_proc_proselabel - 1] = given;
		else
		{
			ncontext = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
										   SECCLASS_DB_PROCEDURE);
			values[Anum_pg_proc_proselabel - 1]
				= CStringGetTextDatum(ncontext);
		}
		nulls[Anum_pg_proc_proselabel - 1] = false;
	}
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
