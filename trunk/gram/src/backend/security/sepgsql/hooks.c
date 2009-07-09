/*
 * src/backend/security/sepgsql/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

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

	if (!new_label)
		datsid = sepgsqlGetDefaultDatabaseSecLabel();
	else
		datsid = securityTransSecLabelIn(DatabaseRelationId,
										 strVal(new_label->arg));

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

Oid
sepgsqlCheckDatabaseRelabel(Oid database_oid, DefElem *new_label)
{
	Oid		datsid;

	if (!sepgsqlIsEnabled())
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}
	datsid = securityTransSecLabelIn(DatabaseRelationId,
									 strVal(new_label->arg));
	/* db_database:{setattr relabelfrom} for older seclabel */
	checkDatabaseCommon(database_oid,
						SEPG_DB_DATABASE__SETATTR |
						SEPG_DB_DATABASE__RELABELFROM, true);
	/* db_database:{relabelto} for newer seclabel */
	sepgsqlClientHasPermsSid(DatabaseRelationId, datsid,
							 SEPG_CLASS_DB_DATABASE,
							 SEPG_DB_DATABASE__RELABELTO,
							 get_database_name(database_oid), true);
	return datsid;
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

	if (!new_label)
		nspsid = (!temp_schema
				  ? sepgsqlGetDefaultSchemaSecLabel(MyDatabaseId)
				  : sepgsqlGetDefaultSchemaTempSecLabel(MyDatabaseId));
	else
		nspsid = securityTransSecLabelIn(NamespaceRelationId,
										 strVal(new_label->arg));

	sepgsqlClientHasPermsSid(NamespaceRelationId, nspsid,
							 (!temp_schema
							  ? SEPG_CLASS_DB_SCHEMA
							  : SEPG_CLASS_DB_SCHEMA_TEMP),
							 SEPG_DB_SCHEMA__CREATE,
							 nspname, true);
	return nspsid;
}

static bool
sepgsqlCheckSchemaCommon(Oid namespace_oid, access_vector_t required, bool abort)
{
	HeapTuple	tuple;
	bool		rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(namespace_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace: %u", namespace_oid);

	rc = sepgsqlClientHasPermsTup(NamespaceRelationId, tuple,
								  (!isAnyTempNamespace(namespace_oid)
								   ? SEPG_CLASS_DB_SCHEMA
								   : SEPG_CLASS_DB_SCHEMA_TEMP),
								  required, abort);
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

Oid
sepgsqlCheckSchemaRelabel(Oid namespace_oid, DefElem *new_label)
{
	Oid		nspsid;

	if (!sepgsqlIsEnabled())
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}
	nspsid = securityTransSecLabelIn(NamespaceRelationId,
									 strVal(new_label->arg));

	/* db_schema:{setattr relabelfrom} for older seclabel */
	sepgsqlCheckSchemaCommon(namespace_oid,
							 SEPG_DB_SCHEMA__SETATTR |
							 SEPG_DB_SCHEMA__RELABELFROM, true);
	/* db_schema:{relabelto} for newer seclabel */
	sepgsqlClientHasPermsSid(NamespaceRelationId, nspsid,
							 !isAnyTempNamespace(namespace_oid)
							 ? SEPG_CLASS_DB_SCHEMA
							 : SEPG_CLASS_DB_SCHEMA_TEMP,
							 SEPG_DB_SCHEMA__RELABELTO,
							 get_namespace_name(namespace_oid), true);
	return nspsid;
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
 * NOTE: db_table/db_sequence:{create} permission is checked
 *       at sepgsqlCreateTableColumns() due to the reason
 *       for implementation.
 */

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
	Form_pg_attribute	attr;
	Relation	attrel;
	SysScanDesc scan;
	ScanKeyData key[1];
	HeapTuple   atttup;
	char		relkind;

	if (!sepgsqlIsEnabled())
		return;

	checkTableCommon(table_oid, SEPG_DB_TABLE__DROP);

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION)
		return;		/* no need to check anymore */

	/* Also checks db_column:{drop} */
	attrel = heap_open(AttributeRelationId, AccessShareLock);

	ScanKeyInit(&key[0],
				Anum_pg_attribute_attrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_oid));

	scan = systable_beginscan(attrel, AttributeRelidNumIndexId, true,
							  SnapshotNow, 1, key);
	while(HeapTupleIsValid(atttup = systable_getnext(scan)))
	{
		attr = (Form_pg_attribute) GETSTRUCT(atttup);
		if (attr->attisdropped)
			continue;

		sepgsqlClientHasPermsTup(AttributeRelationId, atttup,
								 SEPG_CLASS_DB_COLUMN,
								 SEPG_DB_COLUMN__DROP,
								 true);
	}
    systable_endscan(scan);

    heap_close(attrel, AccessShareLock);
}

void
sepgsqlCheckTableSetattr(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__SETATTR);
}

Oid
sepgsqlCheckTableRelabel(Oid table_oid, DefElem *new_label)
{
	Oid		relsid;
	char	relkind;

	if (!sepgsqlIsEnabled())
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION && relkind != RELKIND_SEQUENCE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("Unable to set security label on \"%s\"",
						get_rel_name(table_oid))));

	relsid = securityTransSecLabelIn(RelationRelationId,
									 strVal(new_label->arg));

	/* db_table/db_sequence:{setattr relabelfrom} for older seclabel  */
	checkTableCommon(table_oid,
					 SEPG_DB_TABLE__SETATTR |
					 SEPG_DB_TABLE__RELABELFROM);

	/* db_table/db_sequence:{relabelto} for newer seclabel */
	sepgsqlClientHasPermsSid(RelationRelationId, relsid,
							 (relkind == RELKIND_RELATION
							  ? SEPG_CLASS_DB_TABLE
							  : SEPG_CLASS_DB_SEQUENCE),
							 SEPG_DB_TABLE__RELABELTO,
							 get_rel_name(table_oid), true);
	return relsid;
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

/*
 * NOTE: db_column:{create} is checked on sepgsqlCreateTableColumns()
 *       which is invoked on CREATE TABLE statement.
 *       The sepgsqlCheckColumnCreate() is called on the ALTER TABLE
 *       ... ADD COLUMN path.
 */
Oid
sepgsqlCheckColumnCreate(Oid table_oid, const char *attname, DefElem *new_label)
{
	Oid		secid;
	char	relkind;

	if (!sepgsqlIsEnabled())
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION)
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("Unable to assign security label")));
		return InvalidOid;
	}

	if (!new_label)
		secid = sepgsqlGetDefaultColumnSecLabel(table_oid);
	else
		secid = securityTransSecLabelIn(AttributeRelationId,
										strVal(new_label->arg));

	sepgsqlClientHasPermsSid(AttributeRelationId, secid,
							 SEPG_CLASS_DB_COLUMN,
							 SEPG_DB_COLUMN__CREATE,
							 attname, true);
	return secid;
}

static void
sepgsqlCheckColumnCommon(Oid table_oid, AttrNumber attno,
						 access_vector_t required)
{
	Form_pg_attribute	attr;
	HeapTuple	tuple;
	char		relkind;

	if (!sepgsqlIsEnabled())
		return;

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION)
		return;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(table_oid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for attribute %d of relation %u",
			 attno, table_oid);

	attr = (Form_pg_attribute) GETSTRUCT(tuple);
	if (!attr->attisdropped)
		sepgsqlClientHasPermsTup(AttributeRelationId, tuple,
								 SEPG_CLASS_DB_COLUMN,
								 required, true);
	ReleaseSysCache(tuple);
}

void
sepgsqlCheckColumnDrop(Oid table_oid, AttrNumber attno)
{
	sepgsqlCheckColumnCommon(table_oid, attno, SEPG_DB_COLUMN__DROP);
}

void
sepgsqlCheckColumnSetattr(Oid table_oid, AttrNumber attno)
{
	sepgsqlCheckColumnCommon(table_oid, attno, SEPG_DB_COLUMN__SETATTR);
}

Oid
sepgsqlCheckColumnRelabel(Oid table_oid, AttrNumber attno, DefElem *new_label)
{
	Oid		attsid;
	char	relkind;

	if (!sepgsqlIsEnabled())
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("Unable to set security label on \"%s.%s\"",
						get_rel_name(table_oid),
						get_attname(table_oid, attno))));

	attsid = securityTransSecLabelIn(AttributeRelationId,
									 strVal(new_label->arg));

	/* db_column:{setattr relabelfrom} for older seclabel */
	sepgsqlCheckColumnCommon(table_oid, attno,
							 SEPG_DB_COLUMN__SETATTR |
							 SEPG_DB_COLUMN__RELABELFROM);

	/* db_column:{relabelto} for newer seclabel */
	sepgsqlClientHasPermsSid(AttributeRelationId, attsid,
							 SEPG_CLASS_DB_COLUMN,
							 SEPG_DB_COLUMN__RELABELTO,
							 get_attname(table_oid, attno), true);
	return attsid;
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_procedure object class
 * ------------------------------------------------------------ */
Oid
sepgsqlCheckProcedureCreate(const char *proname,
							Oid namespace_oid, DefElem *new_label)
{
	Oid		prosid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!new_label)
		prosid = sepgsqlGetDefaultProcedureSecLabel(namespace_oid);
	else
		prosid = securityTransSecLabelIn(ProcedureRelationId,
										 strVal(new_label->arg));

	sepgsqlClientHasPermsSid(ProcedureRelationId, prosid,
							 SEPG_CLASS_DB_PROCEDURE,
							 SEPG_DB_PROCEDURE__CREATE,
							 proname, true);

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

Oid
sepgsqlCheckProcedureRelabel(Oid proc_oid, DefElem *new_label)
{
	Oid		prosid;

	if (!sepgsqlIsEnabled())
	{
		if (new_label)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	prosid = securityTransSecLabelIn(ProcedureRelationId,
									 strVal(new_label->arg));

	/* db_procedure:{setattr relabelfrom} for older seclabel */
	sepgsqlCheckProcedureCommon(proc_oid,
								SEPG_DB_PROCEDURE__SETATTR |
								SEPG_DB_PROCEDURE__RELABELFROM, true);
	/* db_procedure:{relabelto} for newer seclabel */
	sepgsqlClientHasPermsSid(ProcedureRelationId, prosid,
							 SEPG_CLASS_DB_PROCEDURE,
							 SEPG_DB_PROCEDURE__RELABELTO,
							 get_func_name(proc_oid), true);
	return prosid;
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
 * sepgsqlCheckObjectDrop
 *   It checks db_xxx:{drop} permission on the given opaque
 *   object, invoked from deleteOneObject()
 */
void
sepgsqlCheckObjectDrop(const ObjectAddress *object)
{
	switch (object->classId)
	{
	case NamespaceRelationId:
		sepgsqlCheckSchemaDrop(object->objectId);
		break;

	case RelationRelationId:
		sepgsqlCheckTableDrop(object->objectId);
		break;

	case AttributeRelationId:
		sepgsqlCheckColumnDrop(object->objectId, object->objectSubId);
		break;

	case ProcedureRelationId:
		sepgsqlCheckProcedureDrop(object->objectId);
		break;

	default:
		/* do nothing in this version */
		break;
	}
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
