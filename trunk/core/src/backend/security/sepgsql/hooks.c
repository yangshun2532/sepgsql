/*
 * src/backend/security/sepgsql/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/syscache.h"

/*
 * ------------------------------------------------------------
 *   Hooks corresponding to db_database object class
 * ------------------------------------------------------------
 */
Oid
sepgsqlCheckDatabaseCreate(const char *datname, DefElem *new_label)
{
	Oid		datsid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	datsid = sepgsqlGetDefaultDatabaseSecLabel();

	sepgsqlClientHasPermsSid(DatabaseRelationId, datsid,
							 SEPG_CLASS_DB_DATABASE,
							 SEPG_DB_DATABASE__CREATE,
							 datname, true);
	return datsid;
}

static bool
checkDatabaseCommon(Oid datoid, access_vector_t perms, bool abort)
{
	HeapTuple		tuple;
	bool			rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datoid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", datoid);

	rc = sepgsqlClientHasPermsTup(DatabaseRelationId, tuple,
								  SEPG_CLASS_DB_DATABASE,
								  perms, abort);
	ReleaseSysCache(tuple);

	return rc;
}

void
sepgsqlCheckDatabaseDrop(Oid database_oid)
{
	checkDatabaseCommon(database_oid,
						SEPG_DB_DATABASE__DROP, true);
}

void
sepgsqlCheckDatabaseSetattr(Oid database_oid)
{
	checkDatabaseCommon(database_oid,
						SEPG_DB_DATABASE__SETATTR, true);
}

bool
sepgsqlCheckDatabaseAccess(Oid database_oid)
{
	return checkDatabaseCommon(database_oid,
							   SEPG_DB_DATABASE__ACCESS, false);
}

bool
sepgsqlCheckDatabaseSuperuser(void)
{
	return checkDatabaseCommon(MyDatabaseId,
							   SEPG_DB_DATABASE__SUPERUSER, false);
}

/*
 * ------------------------------------------------------------
 * Hooks corresponding to db_schema object class
 * ------------------------------------------------------------
 */
Oid
sepgsqlCheckSchemaCreate(const char *nspname, DefElem *new_label, bool temp_schema)
{
	security_class_t
	Oid		nspsid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	nspsid = sepgsqlGetDefaultNamespaceSecLabel(MyDatabaseId, temp_schema);

	sepgsqlClientHasPermsSid(NamespaceRelationId, nspsid,
							 !temp_schema ? SEPG_CLASS_DB_SCHEMA
										  : SEPG_CLASS_DB_SCHEMA_TEMP,
							 SEPG_DB_SCHEMA__CREATE,
							 nspname, true);
	return nspsid;
}

static bool
sepgsqlCheckSchemaCommon(Oid nsid, access_vector_t required, bool abort)
{
	security_class_t	tclass;
	HeapTuple			tuple;
	bool rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nsid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace: %u", nsid);

	tclass = sepgsqlTupleObjectClass(NamespaceRelationId, tuple);
	rc = sepgsqlClientHasPermsTup(NamespaceRelationId, tuple,
								  tclass, required, false);
	ReleaseSysCache(tuple);

	return rc;
}

void
sepgsqlCheckSchemaDrop(Oid namespace_oid)
{
	sepgsqlCheckSchemaCommon(namespace_oid,
							 SEPG_DB_SCHEMA__DROP, true);
}

void
sepgsqlCheckSchemaSetattr(Oid namespace_oid)
{
	sepgsqlCheckSchemaCommon(namespace_oid,
							 SEPG_DB_SCHEMA__SETATTR, true);
}

bool
sepgsqlCheckSchemaSearch(Oid namespace_oid)
{
	return sepgsqlCheckSchemaCommon(namespace_oid,
									SEPG_DB_SCHEMA__SEARCH, false);
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_table object class
 * ------------------------------------------------------------ */

/*
 * sepgsqlCopiedTableCreate
 *   It returns a list of security identifiers for a new table
 *   which is copied from an existing table.
 *   The make_new_heap() creates a copy of relation, then is
 *   shall be swapped with the original one.
 *   Internally, it creates a new table, but we should not
 *   apply default labeling, because it is not a user visible
 *   change.
 */
List *
sepgsqlCopiedTableCreate(Relation srcrel)
{
	Form_pg_attribute	attr;
	HeapTuple	tuple;
	DefElem	   *defel;
	Oid			tblsid;
	Oid			attsid;
	AttrNumber	attnum;
	List	   *result = NIL;

	if (!sepgsqlIsEnabled())
		return NIL;

	/* copy table's security label */
	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(RelationGetRelid(srcrel)),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation: %u",
			 RelationGetRelid(srcrel));

	tblsid = HeapTupleGetSecLabel(tuple);
	defel = makeDefElem(NULL, (Node *)makeInteger(tblsid));
	result = lappend(result, defel);
	ReleaseSysCache(tuple);

	/* copy column's security label */
	attsid = securityMoveSecLabel(AttributeRelationId,
								  RelationRelationId, tblsid);

	for (attnum = FirstLowInvalidHeapAttributeNumber + 1;
		 attnum < RelationGetDescr(srcrel)->natts;
		 attnum++)
	{
		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(RelationGetRelid(srcrel)),
							   Int16GetDatum(attnum),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			continue;

		/* no need to chain when column's label is same as default one */
		if (attsid != HeapTupleGetSecLabel(tuple))
		{
			attr = (Form_pg_attribute) GETSTRUCT(tuple);

			defel = makeDefElem(pstrdup(NameStr(attr->attname)),
								(Node *)makeInteger(HeapTupleGetSecLabel(tuple)));
			result = lappend(result, defel);
		}
		ReleaseSysCache(tuple);
	}

	return result;
}

/*
 * sepgsqlCheckTableCreate
 *   It returns a list of security identifiers of tables/columns
 *   newly created.
 */
List *
sepgsqlCheckTableCreate(CreateStmt *stmt,
						const char *relname, Oid namespace_oid,
						TupleDesc tupdesc, char relkind)
{
	Form_pg_attribute	attr;
	DefElem	   *defel;
	Oid			relsid;
	Oid			attsid;
	Oid			attsid_def;
	int			index;
	List	   *result = NIL;

	if (!sepgsqlIsEnabled())
		return NIL;

	/*
	 * In the current version, we don't give any labels on
	 * relations except for tables, sequences
	 */
	if (relkind != RELKIND_RELATION &&
		relkind != RELKIND_SEQUENCE)
		return NIL;

	/* compute security label of tables/sequences and check it */
	if (relkind == RELKIND_SEQUENCE)
	{
		relsid = sepgsqlGetDefaultSequenceSecLabel(namespace_oid);
		sepgsqlClientHasPermsSid(RelationRelationId, relsid,
								 SEPG_CLASS_DB_SEQUENCE,
								 SEPG_DB_SEQUENCE__CREATE,
								 relname, true);
	}
	else
	{
		relsid = sepgsqlGetDefaultTableSecLabel(namespace_oid);
		sepgsqlClientHasPermsSid(RelationRelationId, relsid,
								 SEPG_CLASS_DB_TABLE,
								 SEPG_DB_TABLE__CREATE,
								 relname, true);
	}
	defel = makeDefElem(NULL, (Node *)makeInteger(relsid));
	result = lappend(result, defel);

	/* compute default column's security label and check it */
	attsid_def = sepgsqlClientCreateSecid(RelationRelationId, relsid,
										  SEPG_CLASS_DB_COLUMN,
										  AttributeRelationId);
	defel = makeDefElem(pstrdup("@__default__@")
						(Node *)makeInteger(attsid_def));
	result = lappend(result, defel);

	for (index = FirstLowInvalidHeapAttributeNumber + 1;
		 index < tupdesc->natts;
		 index++)
	{
		if (index == ObjectIdAttributeNumber && !tupdesc->tdhasoids)
			continue;
		if (index < 0)
			attr = SystemAttributeDefinition(index, tupdesc->tdhasoids);
		else
			attr = tupdesc->attrs[index];

		attname = NameStr(attr);
		/* TODO: check given security label here */
		attsid = attsid_def;
		sepgsqlClientHasPermsSid(AttributeRelationId, attsid,
								 SEPG_CLASS_DB_COLUMN,
								 SEPG_DB_COLUMN__CREATE,
								 attname, true);
	}
	return result;
}

static void
checkTableCommon(Oid table_oid, access_vector_t perms, bool abort)
{
	HeapTuple			tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(table_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", table_oid);

	if (relkind == SEPG_CLASS_DB_TABLE ||
		relkind == SEPG_CLASS_DB_SEQUENCE)
	{
		sepgsqlClientHasPermsTup(RelationRelationId, tuple,
								 relkind == RELKIND_SEQUENCE
									 ? SEPG_CLASS_DB_TABLE
									 : SEPG_CLASS_DB_SEQUENCE,
								 perms, abort);
	}
	ReleaseSysCache(tuple);
}

void
sepgsqlCheckTableDrop(Oid table_oid)
{
	if (!sepgsqlIsEnabled())
		return;
	checkTableCommon(table_oid, SEPG_DB_TABLE__DROP, true);
}

void
sepgsqlCheckTableSetattr(Oid table_oid)
{
	if (!sepgsqlIsEnabled())
		return;
	checkTableCommon(table_oid, SEPG_DB_TABLE__SETATTR, true);
}

void
sepgsqlCheckTableLock(Oid table_oid)
{
	if (!sepgsqlIsEnabled())
		return;

	checkTableCommon(table_oid, SEPG_DB_TABLE__LOCK, true);
}

void
sepgsqlCheckTableTruncate(Relation rel)
{
	if (!sepgsqlIsEnabled())
		return;

	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE, true);
}

void
sepgsqlCheckTableReference(Relation rel, int16 *attnums, int natts)
{
	HeapTuple	tuple;
	int			i;

	if (!sepgsqlIsEnabled())
		return;

	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__REFERENCE, true);

	for (i=0; i < natts; i++)
	{
		tuple = SearchSysCache(ATTNUM,
							   ObjectIdGetDatum(RelationGetRelid(rel)),
							   Int16GetDatum(attnums[i]),
							   0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for attribute %u of %s",
				 attnums[i], RelationGetRelationName(rel));

		sepgsqlClientHasPermsTup(AttributeRelationId, tuple,
								 SEPG_CLASS_DB_COLUMN,
								 SEPG_DB_COLUMN__REFERENCE,
								 true);
		ReleaseSysCache(tuple);
	}
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_sequence object class
 * ------------------------------------------------------------ */
static void
sepgsqlCheckSequenceCommon(Oid seqid, access_vector_t required)
{
	HeapTuple tuple;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(seqid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for sequence: %u", seqid);

	sepgsqlClientHasPermsTup(RelationRelationId, tuple,
							 SEPG_CLASS_DB_SEQUENCE,
							 required, true);
	ReleaseSysCache(tuple);
}

void sepgsqlCheckSequenceGetValue(Oid seqid)
{
	sepgsqlCheckSequenceCommon(seqid, SEPG_DB_SEQUENCE__GET_VALUE);
}

void sepgsqlCheckSequenceNextValue(Oid seqid)
{
	sepgsqlCheckSequenceCommon(seqid, SEPG_DB_SEQUENCE__NEXT_VALUE);
}

void sepgsqlCheckSequenceSetValue(Oid seqid)
{
	sepgsqlCheckSequenceCommon(seqid, SEPG_DB_SEQUENCE__SET_VALUE);
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_column object class
 * ------------------------------------------------------------ */
Oid
sepgsqlCheckColumnCreate(Oid relid, const char *attname, ColumnDef *cdef)
{
	Oid		attsid;
	char	relkind;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	relkind = get_rel_relkind(relid);
	if (relkind != RELKIND_RELATION &&
		relkind != RELKIND_SEQUENCE)
		return InvalidOid;

	attsid = sepgsqlGetDefaultAttributeSecLabel(relid);
	sepgsqlClientHasPermsSid(AttributeRelationId, attsid,
							 SEPG_CLASS_DB_COLUMN,
							 SEPG_DB_COLUMN__CREATE,
							 attname, true);
	return attsid;
}

static void
sepgsqlCheckSequenceCommon(Oid relid, AttrNumber attnum,
						   access_vector_t required)
{
	HeapTuple	tuple;
	char		relkind;

	if (!sepgsqlIsEnabled())
		return;

	relkind = get_rel_relkind(relid);
	if (relkind != RELKIND_RELATION &&
		relkind != RELKIND_SEQUENCE)
		return;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relid),
						   Int16GetDatum(attnum),
						   0, 0);
	sepgsqlClientHasPermsTup(AttributeRelationId, tuple,
							 SEPG_CLASS_DB_COLUMN,
							 required, true);
	ReleaseSysCache(tuple);
}

void
sepgsqlCheckColumnDrop(Oid relid, AttrNumber attnum)
{
	sepgsqlCheckSequenceCommon(relid, attnum, SEPG_DB_COLUMN__DROP);
}

void
sepgsqlCheckColumnSetattr(Oid relid, AttrNumber attnum)
{
	sepgsqlCheckSequenceCommon(relid, attnum, SEPG_DB_COLUMN__SETATTR);
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_procedure object class
 * ------------------------------------------------------------ */
Oid
sepgsqlCheckProcedureCreate(const char *proname, Oid namespace_oid,
							Oid given_secid, HeapTuple oldtup)
{
	Oid		prosid = InvalidOid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!HeapTupleIsValid(oldtup))
	{
		prosid = sepgsqlGetDefaultProcedureSecLabel(namespace_oid);
		sepgsqlClientHasPermsSid(ProcedureRelationId, prosid,
								 SEPG_CLASS_DB_PROCEDURE,
								 SEPG_DB_PROCEDURE__CREATE,
								 proname, true);
	}
	else
	{
		Form_pg_proc	proForm = (Form_pg_proc) GETSTRUCT(oldtup);
		access_vector_t	required = SEPG_DB_PROCEDURE__SETATTR;

		if (OidIsValid(given_secid) &&
			HeapTupleGetSecLabel(oldtup) != given_secid)
			required |= SEPG_DB_PROCEDURE__RELABELFROM;

		sepgsqlClientHasPermsSid(ProcedureRelationId,
								 HeapTupleGetSecLabel(oldtup),
								 SEPG_CLASS_DB_PROCEDURE,
								 required,
								 NameStr(proForm->proname), true);

		if (required & SEPG_DB_PROCEDURE__RELABELFROM)
		{
			sepgsqlClientHasPermsSid(ProcedureRelationId, given_secid,
									 SEPG_CLASS_DB_PROCEDURE,
									 SEPG_DB_PROCEDURE__RELABELTO,
									 proname, true);
			prosid = given_secid;
		}
	}

	return prosid;
}

static bool
sepgsqlCheckProcedureCommon(Oid proc_oid, access_vector_t required, bool abort)
{
	HeapTuple	tuple;
	bool		rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(proc_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for procedure: %u", proc_oid);

	rc = sepgsqlClientHasPermsTup(ProcedureRelationId, tuple,
								  SEPG_CLASS_DB_PROCEDURE,
								  required, abort);
	ReleaseSysCache(tuple);

	return rc;
}

void
sepgsqlCheckProcedureDrop(Oid proc_oid)
{
	sepgsqlCheckProcedureCommon(proc_oid, SEPG_DB_PROCEDURE__DROP, true);
}

void
sepgsqlCheckProcedureSetattr(Oid proc_oid)
{
	sepgsqlCheckProcedureCommon(proc_oid, SEPG_DB_PROCEDURE__SETATTR, true);
}

bool
sepgsqlCheckProcedureExecute(Oid proc_oid)
{
	return sepgsqlCheckProcedureCommon(proc_oid, SEPG_DB_PROCEDURE__EXECUTE, false);
}

/*
 * sepgsqlCheckProcedureEntrypoint
 *   checks whether the given function call causes domain transition,
 *   or not. If it needs a domain transition, it injects a wrapper
 *   function to invoke it under new domain.
 */
struct TrustedProcedureCache
{
	FmgrInfo	flinfo;
	char		newcon[1];
};

static Datum
sepgsqlTrustedProcedure(PG_FUNCTION_ARGS)
{
	struct TrustedProcedureCache *tcache;
	security_context_t	save_context;
	FmgrInfo		   *save_flinfo;
	Datum				result;

	tcache = fcinfo->flinfo->fn_extra;
	Assert(tcache != NULL);

	save_context = sepgsqlSwitchClient(tcache->newcon);
	save_flinfo = fcinfo->flinfo;
	fcinfo->flinfo = &tcache->flinfo;

	PG_TRY();
	{
		result = FunctionCallInvoke(fcinfo);
	}
	PG_CATCH();
	{
		sepgsqlSwitchClient(save_context);
		fcinfo->flinfo = save_flinfo;
		PG_RE_THROW();
	}
	PG_END_TRY();
	sepgsqlSwitchClient(save_context);
	fcinfo->flinfo = save_flinfo;

	return result;
}

void
sepgsqlCheckProcedureEntrypoint(FmgrInfo *flinfo, HeapTuple protup)
{
	struct TrustedProcedureCache   *tcache;
	security_context_t	newcon;

	if (!sepgsqlIsEnabled())
		return;

	newcon = sepgsqlClientCreateLabel(ProcedureRelationId,
									  HeapTupleGetSecLabel(protup),
									  SEPG_CLASS_PROCESS);

	/* Do nothing, if it is not a trusted procedure */
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
		return;

	/* check db_procedure:{entrypoint} */
	sepgsqlClientHasPermsTup(ProcedureRelationId, protup,
							 SEPG_CLASS_DB_PROCEDURE,
							 SEPG_DB_PROCEDURE__ENTRYPOINT,
							 true);

	/* check process:{transition} */
	sepgsqlComputePerms(sepgsqlGetClientLabel(),
						newcon,
						SEPG_CLASS_PROCESS,
						SEPG_PROCESS__TRANSITION,
						NULL, true);

	/* setup trusted procedure */
	tcache = MemoryContextAllocZero(flinfo->fn_mcxt,
							sizeof(*tcache) + strlen(newcon));
	memcpy(&tcache->flinfo, flinfo, sizeof(*flinfo));
	strcpy(tcache->newcon, newcon);
	flinfo->fn_addr = sepgsqlTrustedProcedure;
	flinfo->fn_extra = tcache;
}

/*
 * sepgsqlAllowFunctionInlined
 *   It provides the optimizer a hint whether the given SQL function
 *   can be inlined, or not. If it can be configured as a trusted
 *   procedure, we should not allow it inlined.
 */
bool
sepgsqlAllowFunctionInlined(HeapTuple protup)
{
	security_context_t	newcon;

	if (!sepgsqlIsEnabled())
		return true;

	newcon = sepgsqlClientCreateLabel(ProcedureRelationId,
									  HeapTupleGetSecLabel(protup),
									  SEPG_CLASS_PROCESS);
	/*
	 * If the security context of client is unchange
	 * before or after invocation of the functions,
	 * it is not a trusted procedure, so it can be
	 * inlined due to performance purpose.
	 */
	if (strcmp(sepgsqlGetClientLabel(), newcon) == 0)
		return true;

	return false;
}
