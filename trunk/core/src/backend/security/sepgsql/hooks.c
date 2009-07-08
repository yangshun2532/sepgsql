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
	Oid		nspsid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!temp_schema)
	{
		nspsid = sepgsqlGetDefaultSchemaSecLabel(MyDatabaseId);
		sepgsqlClientHasPermsSid(NamespaceRelationId, nspsid,
								 SEPG_CLASS_DB_SCHEMA,
								 SEPG_DB_SCHEMA__CREATE,
								 nspname, true);
	}
	else
	{
		nspsid = sepgsqlGetDefaultSchemaTempSecLabel(MyDatabaseId);
		sepgsqlClientHasPermsSid(NamespaceRelationId, nspsid,
								 SEPG_CLASS_DB_SCHEMA_TEMP,
								 SEPG_DB_SCHEMA_TEMP__CREATE,
								 nspname, true);
	}
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
								  tclass, required, abort);
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
Oid
sepgsqlCheckTableCreate(Relation new_rel, List *secLabels)
{
	char		relkind = RelationGetForm(new_rel)->relkind;
	Oid			secid = InvalidOid;
	ListCell   *l;

	/*
	 * NOTE: The given secLabels list is the result of
	 * sepgsqlCreateTableSecLabels() which returns
	 * pre-computed security identifiers.
	 */
	if (!sepgsqlIsEnabled())
		return InvalidOid;

	foreach (l, secLabels)
	{
		DefElem	   *defel = lfirst(l);

		if (!defel->defname)
		{
			secid = intVal(defel->arg);
			break;
		}
	}

	switch (relkind)
	{
	case RELKIND_RELATION:
		sepgsqlClientHasPermsSid(RelationRelationId, secid,
								 SEPG_CLASS_DB_TABLE,
								 SEPG_DB_TABLE__CREATE,
								 RelationGetRelationName(new_rel), true);
		break;

	case RELKIND_SEQUENCE:
		sepgsqlClientHasPermsSid(RelationRelationId, secid,
								 SEPG_CLASS_DB_SEQUENCE,
								 SEPG_DB_SEQUENCE__CREATE,
								 RelationGetRelationName(new_rel), true);
		break;
	default:
		/* do not check anything now */
		break;
	}

	return secid;
}

static void
checkTableCommon(Oid table_oid, access_vector_t required)
{
	HeapTuple	tuple;
	char		relkind;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(table_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", table_oid);

	relkind = ((Form_pg_class) GETSTRUCT(tuple))->relkind;
	switch (relkind)
	{
	case RELKIND_RELATION:
		sepgsqlClientHasPermsTup(RelationRelationId, tuple,
								 SEPG_CLASS_DB_TABLE,
								 required, true);
		break;

	case RELKIND_SEQUENCE:
		sepgsqlClientHasPermsTup(RelationRelationId, tuple,
								 SEPG_CLASS_DB_SEQUENCE,
								 required, true);
		break;

	default:
		/* do nothing in this version */
		break;
	}
	ReleaseSysCache(tuple);
}

void
sepgsqlCheckTableDrop(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__DROP);
}

void
sepgsqlCheckTableSetattr(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__SETATTR);
}

void
sepgsqlCheckTableLock(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__LOCK);
}

void
sepgsqlCheckTableTruncate(Relation rel)
{
	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE);
}

void
sepgsqlCheckTableReference(Relation rel, int16 *attnums, int natts)
{
	HeapTuple	tuple;
	int			i;

	if (!sepgsqlIsEnabled())
		return;

	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__REFERENCE);

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
sepgsqlCheckColumnCreate(Form_pg_attribute attr, char relkind, List *secLabels)
{
	Oid			relsid = InvalidOid;
	Oid			attsid = InvalidOid;
	ListCell   *l;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (relkind != RELKIND_RELATION)
		return InvalidOid;

	foreach (l, secLabels)
	{
		DefElem	   *defel = lfirst(l);

		if (!defel->defname)
			relsid = intVal(defel->arg);
		else if (strcmp(defel->defname, NameStr(attr->attname)) == 0)
		{
			attsid = intVal(defel->arg);
			break;
		}
	}

	if (!OidIsValid(attsid))
		attsid = sepgsqlClientCreateSecid(RelationRelationId, relsid,
										  SEPG_CLASS_DB_COLUMN,
										  AttributeRelationId);

	sepgsqlClientHasPermsSid(AttributeRelationId, attsid,
							 SEPG_CLASS_DB_COLUMN,
							 SEPG_DB_COLUMN__CREATE,
							 NameStr(attr->attname), true);
	return attsid;
}

void
sepgsqlCheckColumnCreateAT(Relation rel, Node *cdef)
{
	ColumnDef  *colDef = (ColumnDef *)cdef;
	char		relkind = RelationGetForm(rel)->relkind;
	Oid			relid = RelationGetRelid(rel);
	Oid			secid;

	if (!sepgsqlIsEnabled())
	{
		/*
		 * we cannot use SECURITY_LABEL option when SE-PostgreSQL
		 * is unavailable.
		 */
		if (colDef->secLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return;
	}

	if (relkind != RELKIND_RELATION)
	{
		if (colDef->secLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("Unable to assign security label")));
		return;
	}

	if (!colDef->secLabel)
		secid = sepgsqlGetDefaultColumnSecLabel(relid);
	else if (IsA(colDef->secLabel, Integer))
		secid = intVal(colDef->secLabel);	/* already translated */
	else
		secid = sepgsqlGivenSecLabelIn(AttributeRelationId,
									   (DefElem *)colDef->secLabel);

	sepgsqlClientHasPermsSid(AttributeRelationId, secid,
							 SEPG_CLASS_DB_COLUMN,
							 SEPG_DB_COLUMN__CREATE,
							 colDef->colname, true);
	colDef->secLabel = (Node *) makeInteger(secid);
}

static void
sepgsqlCheckColumnCommon(Relation rel, const char *attname,
						 access_vector_t required)
{
	HeapTuple	tuple;
	char		relkind;

	if (!sepgsqlIsEnabled())
		return;

	relkind = RelationGetForm(rel)->relkind;
	if (relkind != RELKIND_RELATION)
		return;

	tuple = SearchSysCacheAttName(RelationGetRelid(rel), attname);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for %s.%s",
			 RelationGetRelationName(rel), attname);

	sepgsqlClientHasPermsTup(AttributeRelationId, tuple,
							 SEPG_CLASS_DB_COLUMN,
							 required, true);

	ReleaseSysCache(tuple);
}

void
sepgsqlCheckColumnDrop(Relation rel, const char *attname)
{
	sepgsqlCheckColumnCommon(rel, attname, SEPG_DB_COLUMN__DROP);
}

void
sepgsqlCheckColumnSetattr(Relation rel, const char *attname)
{
	sepgsqlCheckColumnCommon(rel, attname, SEPG_DB_COLUMN__SETATTR);
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
