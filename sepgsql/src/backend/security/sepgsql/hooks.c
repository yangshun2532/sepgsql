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
#include "catalog/pg_foreign_data_wrapper.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_opfamily.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_ts_dict.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_type.h"
#include "catalog/pg_security.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * ------------------------------------------------------------
 *   Hooks corresponding to db_database object class
 * ------------------------------------------------------------
 *
 * sepgsqlCheckDatabaseInstallModule
 *   checks db_database:{install_module} permission when the client
 *   tries to install a dynamic link library on the current databse.
 *
 * sepgsqlCheckDatabaseLoadModule
 *   checks capability of the database when it loads a certain DLL
 *   into its process address space.
 */
Oid
sepgsqlCheckDatabaseCreate(const char *datname, DefElem *newLabel)
{
	sepgsql_sid_t	datSid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!newLabel)
		datSid = sepgsqlGetDefaultDatabaseSecid();
	else
	{
		datSid.relid = DatabaseRelationId;
		datSid.secid = securityTransSecLabelIn(datSid.relid,
											   strVal(newLabel->arg));
	}

	sepgsqlClientHasPerms(datSid,
						  SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__CREATE,
						  datname, true);
	return datSid.secid;
}

static bool
checkDatabaseCommon(Oid datOid, uint32 required, bool abort)
{
	HeapTuple		tuple;
	sepgsql_sid_t	datSid;
	uint16			tclass;
	const char	   *auname;
	bool			rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(datOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", datOid);

	auname = NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname);
	datSid = sepgsqlGetTupleContext(DatabaseRelationId,
									tuple, &tclass);
	rc = sepgsqlClientHasPerms(datSid,
							   tclass, required,
							   auname, abort);

	ReleaseSysCache(tuple);

	return rc;
}

void
sepgsqlCheckDatabaseDrop(Oid datOid)
{
	checkDatabaseCommon(datOid, SEPG_DB_DATABASE__DROP, true);
}

void
sepgsqlCheckDatabaseSetattr(Oid datOid)
{
	checkDatabaseCommon(datOid, SEPG_DB_DATABASE__SETATTR, true);
}

Oid
sepgsqlCheckDatabaseRelabel(Oid datOid, DefElem *newLabel)
{
	sepgsql_sid_t	datSid;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}
	datSid.relid = DatabaseRelationId;
	datSid.secid = securityTransSecLabelIn(datSid.relid,
										   strVal(newLabel->arg));
	/* db_database:{setattr relabelfrom} for older seclabel */
	checkDatabaseCommon(datOid,
						SEPG_DB_DATABASE__SETATTR |
						SEPG_DB_DATABASE__RELABELFROM, true);
	/* db_database:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(datSid,
						  SEPG_CLASS_DB_DATABASE,
						  SEPG_DB_DATABASE__RELABELTO,
						  get_database_name(datOid), true);
	return datSid.secid;
}

void
sepgsqlCheckDatabaseAccess(Oid datOid)
{
	if (!checkDatabaseCommon(datOid, SEPG_DB_DATABASE__ACCESS, false))
		ereport(FATAL,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: security policy violation")));
}

bool
sepgsqlCheckDatabaseSuperuser(void)
{
	return checkDatabaseCommon(MyDatabaseId,
							   SEPG_DB_DATABASE__SUPERUSER, false);
}

void
sepgsqlCheckDatabaseLoadModule(const char *filename)
{
	HeapTuple		tuple;
	security_context_t filecon;
	security_context_t dbcon;

	if (!sepgsqlIsEnabled())
		return;
	/*
	 * It assumes preloaded libraries are secure,
	 * because it can be set up using guc variable
	 * not any SQL statements.
	 */
	if (GetProcessingMode() == InitProcessing)
		return;

	/* Get database context */
	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database: %u", MyDatabaseId);

	dbcon = securityRawSecLabelOut(DatabaseRelationId,
								   HeapTupleGetSecid(tuple));
	ReleaseSysCache(tuple);

	/* Get library context */
	if (getfilecon_raw(filename, &filecon) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not access file \"%s\": %m", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(dbcon,
							filecon,
							SEPG_CLASS_DB_DATABASE,
							SEPG_DB_DATABASE__LOAD_MODULE,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(filecon);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(filecon);
}

/*
 * ------------------------------------------------------------
 * Hooks corresponding to db_schema object class
 * ------------------------------------------------------------
 */

Oid
sepgsqlCheckSchemaCreate(const char *nspName, DefElem *newLabel, bool isTemp)
{
	sepgsql_sid_t	nspSid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!newLabel)
	{
		nspSid = (!isTemp
				  ? sepgsqlGetDefaultSchemaSecid(MyDatabaseId)
				  : sepgsqlGetDefaultSchemaTempSecid(MyDatabaseId));
	}
	else
	{
		nspSid.relid = NamespaceRelationId;
		nspSid.secid = securityTransSecLabelIn(nspSid.relid,
											   strVal(newLabel->arg));
	}
	sepgsqlClientHasPerms(nspSid,
						  (!isTemp
						   ? SEPG_CLASS_DB_SCHEMA
						   : SEPG_CLASS_DB_SCHEMA_TEMP),
						  SEPG_DB_SCHEMA__CREATE,
						  nspName, true);
	return nspSid.secid;
}

static bool
checkSchemaCommon(Oid nspOid, uint32 required, bool abort)
{
	HeapTuple		tuple;
	sepgsql_sid_t	nspSid;
	uint16			tclass;
	const char	   *auname;
	bool			rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(NAMESPACEOID,
						   ObjectIdGetDatum(nspOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for namespace: %u", nspOid);

	nspSid = sepgsqlGetTupleContext(NamespaceRelationId,
									tuple, &tclass);

	auname = NameStr(((Form_pg_namespace) GETSTRUCT(tuple))->nspname);
	rc = sepgsqlClientHasPerms(nspSid, tclass, required,
							   auname, abort);

	ReleaseSysCache(tuple);

	return rc;
}

void
sepgsqlCheckSchemaDrop(Oid nspOid)
{
	checkSchemaCommon(nspOid, SEPG_DB_SCHEMA__DROP, true);
}

void
sepgsqlCheckSchemaSetattr(Oid nspOid)
{
	checkSchemaCommon(nspOid, SEPG_DB_SCHEMA__SETATTR, true);
}

Oid
sepgsqlCheckSchemaRelabel(Oid nspOid, DefElem *newLabel)
{
	sepgsql_sid_t	nspSid;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}
	nspSid.relid = NamespaceRelationId;
	nspSid.secid = securityTransSecLabelIn(nspSid.relid,
										   strVal(newLabel->arg));

	/* db_schema:{setattr relabelfrom} for older seclabel */
	checkSchemaCommon(nspOid,
					  SEPG_DB_SCHEMA__SETATTR |
					  SEPG_DB_SCHEMA__RELABELFROM, true);
	/* db_schema:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(nspSid,
						  !isAnyTempNamespace(nspOid)
						  ? SEPG_CLASS_DB_SCHEMA
						  : SEPG_CLASS_DB_SCHEMA_TEMP,
						  SEPG_DB_SCHEMA__RELABELTO,
						  get_namespace_name(nspOid), true);
	return nspSid.secid;
}

void
sepgsqlCheckSchemaAddName(Oid nspOid)
{
	checkSchemaCommon(nspOid, SEPG_DB_SCHEMA__ADD_NAME, true);
}

void
sepgsqlCheckSchemaRemoveName(Oid nspOid)
{
	checkSchemaCommon(nspOid, SEPG_DB_SCHEMA__REMOVE_NAME, true);
}

bool
sepgsqlCheckSchemaSearch(Oid nspOid, bool abort)
{
	return checkSchemaCommon(nspOid, SEPG_DB_SCHEMA__SEARCH, abort);
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
sepgsqlCheckColumnCreate(Oid table_oid, const char *attname, DefElem *newLabel)
{
	sepgsql_sid_t	attSid;
	char			relkind;
	char			auname[NAMEDATALEN * 2 + 3];

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(table_oid);
	if (relkind != RELKIND_RELATION)
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("Unable to assign security label")));
		return InvalidOid;
	}

	if (!newLabel)
		attSid = sepgsqlGetDefaultColumnSecid(table_oid);
	else
	{
		attSid.relid = AttributeRelationId;
		attSid.secid = securityTransSecLabelIn(attSid.relid,
											   strVal(newLabel->arg));
	}

	sprintf(auname, "%s.%s", get_rel_name(table_oid), attname);
	sepgsqlClientHasPerms(attSid,
						  SEPG_CLASS_DB_COLUMN,
						  SEPG_DB_COLUMN__CREATE,
						  auname, true);
	return attSid.secid;
}

static void
checkColumnCommon(Oid relOid, AttrNumber attno, uint32 required)
{
	Form_pg_attribute	attr;
	sepgsql_sid_t		attSid;
	HeapTuple			tuple;
	uint16				tclass;
	char				auname[2 * NAMEDATALEN + 3];
	char				relkind;

	if (!sepgsqlIsEnabled())
		return;

	relkind = get_rel_relkind(relOid);
	if (relkind != RELKIND_RELATION)
		return;

	tuple = SearchSysCache(ATTNUM,
						   ObjectIdGetDatum(relOid),
						   Int16GetDatum(attno),
						   0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for attribute %d of relation %u",
			 attno, relOid);

	attr = (Form_pg_attribute) GETSTRUCT(tuple);
	if (!attr->attisdropped)
	{
		sprintf(auname, "%s.%s",
				get_rel_name(relOid),
				NameStr(attr->attname));
		attSid = sepgsqlGetTupleContext(AttributeRelationId,
										tuple, &tclass);
		sepgsqlClientHasPerms(attSid, tclass, required,
							  auname, true);
	}

	ReleaseSysCache(tuple);
}

void
sepgsqlCheckColumnDrop(Oid relOid, AttrNumber attno)
{
	checkColumnCommon(relOid, attno, SEPG_DB_COLUMN__DROP);
}

void
sepgsqlCheckColumnSetattr(Oid relOid, AttrNumber attno)
{
	checkColumnCommon(relOid, attno, SEPG_DB_COLUMN__SETATTR);
}

Oid
sepgsqlCheckColumnRelabel(Oid relOid, AttrNumber attno, DefElem *newLabel)
{
	sepgsql_sid_t	attSid;
	char			relkind;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	relkind = get_rel_relkind(relOid);
	if (relkind != RELKIND_RELATION)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("Unable to set security label on \"%s.%s\"",
						get_rel_name(relOid),
						get_attname(relOid, attno))));

	attSid.relid = AttributeRelationId;
	attSid.secid = securityTransSecLabelIn(attSid.relid,
										   strVal(newLabel->arg));

	/* db_column:{setattr relabelfrom} for older seclabel */
	checkColumnCommon(relOid, attno,
					  SEPG_DB_COLUMN__SETATTR |
					  SEPG_DB_COLUMN__RELABELFROM);

	/* db_column:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(attSid,
						  SEPG_CLASS_DB_COLUMN,
						  SEPG_DB_COLUMN__RELABELTO,
						  get_attname(relOid, attno), true);
	return attSid.secid;
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_table object class
 * ------------------------------------------------------------ */

/*
 * NOTE: db_table/db_sequence:{create} permission is checked
 *       at sepgsqlCreateTableColumns() due to the reason
 *       for implementation.
 *
 * sepgsqlCheckTableReference
 *   checks db_table:{reference} and db_column:{reference} permission
 *   when the client tries to set up a foreign key constraint on the
 *   certain tables and columns.
 */

static void
checkTableCommon(Oid table_oid, access_vector_t required)
{
	HeapTuple		tuple;
	sepgsql_sid_t	relSid;
	uint16			tclass;
	const char	   *auname;

	if (!sepgsqlIsEnabled())
		return;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(table_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", table_oid);

	auname = NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname);
	relSid = sepgsqlGetTupleContext(RelationRelationId,
									tuple, &tclass);
	sepgsqlClientHasPerms(relSid, tclass, required,
						  auname, true);
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

Oid
sepgsqlCheckTableRelabel(Oid table_oid, DefElem *newLabel)
{
	sepgsql_sid_t	relSid;
	char			relkind;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
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

	relSid.relid = RelationRelationId;
	relSid.secid = securityTransSecLabelIn(relSid.relid,
										   strVal(newLabel->arg));

	/* db_table/db_sequence:{setattr relabelfrom} for older seclabel  */
	checkTableCommon(table_oid,
					 SEPG_DB_TABLE__SETATTR |
					 SEPG_DB_TABLE__RELABELFROM);

	/* db_table/db_sequence:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(relSid,
						  (relkind == RELKIND_RELATION
						   ? SEPG_CLASS_DB_TABLE
						   : SEPG_CLASS_DB_SEQUENCE),
						  SEPG_DB_TABLE__RELABELTO,
						  get_rel_name(table_oid), true);
	return relSid.secid;
}

void
sepgsqlCheckTableLock(Oid table_oid)
{
	checkTableCommon(table_oid, SEPG_DB_TABLE__LOCK);
}

void
sepgsqlCheckTableTruncate(Relation rel)
{
	HeapScanDesc		scan;
	HeapTuple			tuple;
	sepgsql_sid_t		tupSid;
	uint16				tclass;

	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{delete} permission */
	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE);

	/* row-level access control is enabled? */
	if (!sepostgresql_row_level)
		return;

	/* check db_tuple:{delete} permission */
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		tupSid = sepgsqlGetTupleContext(RelationGetRelid(rel),
										tuple, &tclass);
		sepgsqlClientHasPerms(tupSid,
							  tclass, SEPG_DB_TUPLE__DELETE,
							  NULL, true);
	}
	heap_endscan(scan);
}

void
sepgsqlCheckTableReference(Relation rel, int16 *attnums, int natts)
{
	int		i;

	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__REFERENCE);

	for (i=0; i < natts; i++)
	{
		checkColumnCommon(RelationGetRelid(rel),
						  attnums[i], SEPG_DB_COLUMN__REFERENCE);
	}
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_sequence object class
 * ------------------------------------------------------------ */
void sepgsqlCheckSequenceGetValue(Oid seqOid)
{
	checkTableCommon(seqOid, SEPG_DB_SEQUENCE__GET_VALUE);
}

void sepgsqlCheckSequenceNextValue(Oid seqOid)
{
	checkTableCommon(seqOid, SEPG_DB_SEQUENCE__NEXT_VALUE);
}

void sepgsqlCheckSequenceSetValue(Oid seqOid)
{
	checkTableCommon(seqOid, SEPG_DB_SEQUENCE__SET_VALUE);
}

/* ------------------------------------------------------------ *
 *   Hooks corresponding to db_procedure object class
 * ------------------------------------------------------------ */
static bool
checkProcedureCommon(Oid procOid, uint32 required, bool abort)
{
	sepgsql_sid_t	proSid;
	HeapTuple		tuple;
	uint16			tclass;
	const char	   *auname;
	bool			rc;

	if (!sepgsqlIsEnabled())
		return true;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(procOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for procedure: %u", procOid);

	auname = NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname);
	proSid = sepgsqlGetTupleContext(ProcedureRelationId,
									tuple, &tclass);
	rc = sepgsqlClientHasPerms(proSid, tclass, required,
							   auname, abort);

	ReleaseSysCache(tuple);

	return rc;
}

Oid
sepgsqlCheckProcedureCreate(const char *procName, Oid procOid,
							Oid procNsp, Oid procLang, DefElem *newLabel)
{
	sepgsql_sid_t	proSid;
	HeapTuple		tuple;
	uint32			required;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	if (!OidIsValid(procOid))
	{
		/* create a new function */
		required = SEPG_DB_PROCEDURE__CREATE;
		if (!newLabel)
			proSid = sepgsqlGetDefaultProcedureSecid(procNsp);
		else
		{
			proSid.relid = ProcedureRelationId;
			proSid.secid = securityTransSecLabelIn(proSid.relid,
												   strVal(newLabel->arg));
		}
	}
	else if (!newLabel)
	{
		/* replace an existing function, without any label */
		required = SEPG_DB_PROCEDURE__SETATTR;
		tuple = SearchSysCache(PROCOID,
							   ObjectIdGetDatum(procOid),
							   0, 0, 0);
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for procedure: %u", procOid);

		proSid = sepgsqlGetTupleContext(ProcedureRelationId,
										tuple, NULL);
		ReleaseSysCache(tuple);
	}
	else
	{
		/* replace an existing function, with relabeling */
		checkProcedureCommon(procOid,
							 SEPG_DB_PROCEDURE__SETATTR |
							 SEPG_DB_PROCEDURE__RELABELFROM, true);

		required = SEPG_DB_PROCEDURE__RELABELTO;
		proSid.relid = ProcedureRelationId;
		proSid.secid = securityTransSecLabelIn(proSid.relid,
											   strVal(newLabel->arg));
	}

	/* Procedural language is trusted? */
	tuple = SearchSysCache(LANGOID,
						   ObjectIdGetDatum(procLang),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for procedural langugage: %u", procLang);

	if (!((Form_pg_language) GETSTRUCT(tuple))->lanpltrusted)
		required |= SEPG_DB_PROCEDURE__UNTRUSTED;

	ReleaseSysCache(tuple);

	/* check it */
	sepgsqlClientHasPerms(proSid,
						  SEPG_CLASS_DB_PROCEDURE, required,
						  procName, true);

	return proSid.secid;
}

void
sepgsqlCheckProcedureDrop(Oid procOid)
{
	checkProcedureCommon(procOid, SEPG_DB_PROCEDURE__DROP, true);
}

void
sepgsqlCheckProcedureSetattr(Oid procOid)
{
	checkProcedureCommon(procOid, SEPG_DB_PROCEDURE__SETATTR, true);
}

Oid
sepgsqlCheckProcedureRelabel(Oid procOid, DefElem *newLabel)
{
	sepgsql_sid_t	proSid;

	if (!sepgsqlIsEnabled())
	{
		if (newLabel)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux is disabled now")));
		return InvalidOid;
	}

	proSid.relid = ProcedureRelationId;
	proSid.secid = securityTransSecLabelIn(proSid.relid,
										   strVal(newLabel->arg));

	/* db_procedure:{setattr relabelfrom} for older seclabel */
	checkProcedureCommon(procOid,
						 SEPG_DB_PROCEDURE__SETATTR |
						 SEPG_DB_PROCEDURE__RELABELFROM, true);
	/* db_procedure:{relabelto} for newer seclabel */
	sepgsqlClientHasPerms(proSid,
						  SEPG_CLASS_DB_PROCEDURE,
						  SEPG_DB_PROCEDURE__RELABELTO,
						  get_func_name(procOid), true);
	return proSid.secid;
}

void
sepgsqlCheckProcedureExecute(Oid procOid)
{
	checkProcedureCommon(procOid, SEPG_DB_PROCEDURE__EXECUTE, true);
}

/*
 * sepgsqlCheckProcedureInstall
 *
 * It should be checked when a procedure is installed as a part of system
 * internal stuff.
 */
void
sepgsqlCheckProcedureInstall(Oid procOid)
{
	if (OidIsValid(procOid))
		checkProcedureCommon(procOid, SEPG_DB_PROCEDURE__INSTALL, true);
}

/*
 * sepgsqlHintProcedureInlined
 *
 * It provides a hint whether the given sql procedure can be inlined, or not.
 */
bool
sepgsqlHintProcedureInlined(HeapTuple protup)
{
	security_context_t	newcon;
	sepgsql_sid_t		proSid;

	if (!sepgsqlIsEnabled())
		return true;

	if (!checkProcedureCommon(HeapTupleGetOid(protup),
							  SEPG_DB_PROCEDURE__EXECUTE, false))
		return false;
	/*
	 * If the security context of client is unchange
	 * before or after invocation of the functions,
	 * it is not a trusted procedure, so it can be
	 * inlined due to performance purpose.
	 */
	proSid = sepgsqlGetTupleContext(ProcedureRelationId,
									protup, NULL);

	newcon = sepgsqlClientCreateLabel(proSid, SEPG_CLASS_PROCESS);

	if (strcmp(sepgsqlGetClientLabel(), newcon) == 0)
		return true;

	return false;
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
	sepgsql_sid_t		proSid;

	if (!sepgsqlIsEnabled())
		return;

	proSid = sepgsqlGetTupleContext(ProcedureRelationId,
									protup, NULL);

	newcon = sepgsqlClientCreateLabel(proSid, SEPG_CLASS_PROCESS);

	/* Do nothing, if it is not a trusted procedure */
	if (strcmp(newcon, sepgsqlGetClientLabel()) == 0)
		return;

	/* check db_procedure:{entrypoint} */
	sepgsqlClientHasPerms(proSid,
						  SEPG_CLASS_DB_PROCEDURE,
						  SEPG_DB_PROCEDURE__ENTRYPOINT,
						  NULL, true);

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
 * sepgsqlCheckBlobCreate
 *   assigns a default security label and checks db_blob:{create}
 */
void
sepgsqlCheckBlobCreate(Relation rel, HeapTuple lotup)
{
	sepgsql_sid_t	loSid;
	Oid				relid = RelationGetRelid(rel);

	if (!sepgsqlIsEnabled())
		return;

	/* set a default security context */
	sepgsqlSetDefaultSecid(rel, lotup);

	loSid = sepgsqlGetTupleContext(relid, lotup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__CREATE,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobDrop
 *   checks db_blob:{drop} permission
 */
void
sepgsqlCheckBlobDrop(Relation rel, HeapTuple lotup)
{
	sepgsql_sid_t	loSid;
	Oid				relid = RelationGetRelid(rel);

	if (!sepgsqlIsEnabled())
		return;

	loSid = sepgsqlGetTupleContext(relid, lotup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__DROP,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobRead
 *   checks db_blob:{read} permission
 */
void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__READ,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobWrite
 *   check db_blob:{write} permission
 */
void
sepgsqlCheckBlobWrite(LargeObjectDesc *lobj)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__WRITE,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobGetattr
 *   check db_blob:{getattr} permission
 */
void
sepgsqlCheckBlobGetattr(HeapTuple tuple)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = HeapTupleGetSecid(tuple);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__GETATTR,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobSetattr
 *   check db_blob:{setattr} permission
 */
void
sepgsqlCheckBlobSetattr(HeapTuple tuple)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	loSid.relid = LargeObjectRelationId;
	loSid.secid = HeapTupleGetSecid(tuple);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__SETATTR,
						  NULL, true);
}

/*
 * sepgsqlCheckBlobExport
 *   check db_blob:{read export} and file:{write} permission
 */
void
sepgsqlCheckBlobExport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	/* db_blob:{read export} */
	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__READ | SEPG_DB_BLOB__EXPORT,
						  NULL, true);
	/* file:{write} */
	sepgsqlCheckFileWrite(fdesc, filename);
}

/*
 * sepgsqlCheckBlobImport
 *   check db_blob:{write import} and file:{read} permission
 */
void
sepgsqlCheckBlobImport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename)
{
	sepgsql_sid_t	loSid;

	if (!sepgsqlIsEnabled())
		return;

	/* db_blob:{write import} */
	loSid.relid = LargeObjectRelationId;
	loSid.secid = lobj->secid;
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__WRITE | SEPG_DB_BLOB__IMPORT,
						  NULL, true);
	/* file:{read} */
	sepgsqlCheckFileRead(fdesc, filename);
}

/*
 * sepgsqlCheckBlobRelabel
 *   check db_blob:{setattr relabelfrom relabelto}
 */
void
sepgsqlCheckBlobRelabel(HeapTuple oldtup, HeapTuple newtup)
{
	sepgsql_sid_t		loSid;
	access_vector_t		required = SEPG_DB_BLOB__SETATTR;

	if (HeapTupleGetSecid(oldtup) != HeapTupleGetSecid(newtup))
		required |= SEPG_DB_BLOB__RELABELFROM;

	/* db_blob:{setattr relabelfrom} */
	loSid = sepgsqlGetTupleContext(LargeObjectRelationId, oldtup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  required,
						  NULL, true);

	if ((required & SEPG_DB_BLOB__RELABELFROM) == 0)
		return;

	/* db_blob:{relabelto} */
	loSid = sepgsqlGetTupleContext(LargeObjectRelationId, newtup, NULL);
	sepgsqlClientHasPerms(loSid,
						  SEPG_CLASS_DB_BLOB,
						  SEPG_DB_BLOB__RELABELTO,
						  NULL, true);
}

/*
 * sepgsqlCheckSysobjCreate
 *
 * It checks db_tuple:{insert} for system catalog
 */
Oid
sepgsqlCheckSysobjCreate(Oid relid, const char *auditName)
{
	sepgsql_sid_t	sysSid;

	if (!sepgsqlIsEnabled())
		return InvalidOid;

	sysSid = sepgsqlGetDefaultTupleSecid(relid);

	sepgsqlClientHasPerms(sysSid,
						  SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__INSERT,
						  auditName, true);

	return sysSid.secid;
}

/*
 * sepgsqlCheckSysobjGetattr
 *
 * It checks db_tuple:{select} for system catalog
 */
void
sepgsqlCheckSysobjGetattr(Oid relid, Oid secid, const char *auditName)
{
	sepgsql_sid_t	sysSid;

	if (!sepgsqlIsEnabled())
		return;

	sysSid.relid = relid;
	sysSid.secid = secid;
	sepgsqlClientHasPerms(sysSid,
						  SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__SELECT,
						  auditName, true);
}

/*
 * sepgsqlCheckSysobjSetattr
 *
 * It checks db_tuple:{update} for system catalog
 */
void
sepgsqlCheckSysobjSetattr(Oid relid, Oid secid, const char *auditName)
{
	sepgsql_sid_t	sysSid;

	if (!sepgsqlIsEnabled())
		return;

	sysSid.relid = relid;
	sysSid.secid = secid;
	sepgsqlClientHasPerms(sysSid,
						  SEPG_CLASS_DB_TUPLE,
						  SEPG_DB_TUPLE__UPDATE,
						  auditName, true);
}

/*
 * sepgsqlCheckSysobjDrop
 *   It checks db_xxx:{drop} permission on the given opaque
 *   object, invoked from deleteOneObject()
 */
void
sepgsqlCheckSysobjDrop(const ObjectAddress *object)
{
	sepgsql_sid_t	tsid;
	uint16			tclass;
	const char	   *auname[2 * NAMEDATALEN + 10];

	switch (object->classId)
	{
	case TypeRelationId:
		{
			Form_pg_type	typForm;
			HeapTuple		typtup;

			typtup = SearchSysCache(TYPEOID,
									ObjectIdGetDatum(object->objectId),
									0, 0, 0);
			if (!HeapTupleIsValid(typtup))
				elog(ERROR, "cache lookup failed for type: %u", object->objectId);

			typForm = (Form_pg_type) GETSTRUCT(typtup);
			/*
			 * No need to check for composite type and implicitly
			 * declared array type here.
			 */
			if (!(typForm->typtype == TYPTYPE_COMPOSITE ||
				  (typForm->typtype == TYPTYPE_BASE &&
				   !OidIsValid(typForm->typarray))))
			{
				tsid = sepgsqlGetTupleContext(object->classId, typtup, &tclass);
				sepgsqlClientHasPerms(tsid, tclass,
									  SEPG_DB_TUPLE__DELETE,
									  NULL, true);
			}
			ReleaseSysCache(typtup);
		}
		break;

	default:
		tsid = sepgsqlGetSysobjContext(object->classId,
									   object->objectId,
									   object->objectSubId,
									   &tclass);
		sepgsqlClientHasPerms(tsid, tclass,
							  SEPG_DB_TUPLE__DELETE,
							  NULL, true);
		break;
	}
}

/*
 * sepgsqlCheckFileRead
 * sepgsqlCheckFileWrite
 *   check file:{read} or file:{write} permission on the given file,
 *   and raises an error if violated.
 */
static void
checkFileCommon(int fdesc, const char *filename, access_vector_t perms)
{
	security_context_t	context;
	security_class_t	tclass;

	if (!sepgsqlIsEnabled())
		return;

	tclass = sepgsqlFileObjectClass(fdesc);

	if (fgetfilecon_raw(fdesc, &context) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not get context of %s", filename)));
	PG_TRY();
	{
		sepgsqlComputePerms(sepgsqlGetClientLabel(),
							context,
							tclass,
							perms,
							filename, true);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);
}

void
sepgsqlCheckFileRead(int fdesc, const char *filename)
{
	checkFileCommon(fdesc, filename, SEPG_FILE__READ);
}

void
sepgsqlCheckFileWrite(int fdesc, const char *filename)
{
	checkFileCommon(fdesc, filename, SEPG_FILE__WRITE);
}
