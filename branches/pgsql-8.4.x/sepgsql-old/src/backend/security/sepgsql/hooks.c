/*
 * src/backend/security/sepgsql/hooks.c
 *    SE-PostgreSQL security hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_aggregate.h"
#include "catalog/pg_am.h"
#include "catalog/pg_amop.h"
#include "catalog/pg_amproc.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_conversion.h"
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
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "security/sepgsql.h"
#include "storage/bufmgr.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * sepgsqlCheckDatabaseAccess
 *   checks db_database:{access} permission when the client logs-in
 *   the given database.
 *
 * sepgsqlCheckDatabaseSuperuser
 *   checks db_database:{superuser} permission when the client tries
 *   to perform as a superuser on the given databse.
 *
 * sepgsqlCheckDatabaseInstallModule
 *   checks db_database:{install_module} permission when the client
 *   tries to install a dynamic link library on the current databse.
 *
 * sepgsqlCheckDatabaseLoadModule
 *   checks capability of the database when it loads a certain DLL
 *   into its process address space.
 */
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

bool
sepgsqlCheckDatabaseAccess(Oid database_oid)
{
	return checkDatabaseCommon(database_oid,
							   SEPG_DB_DATABASE__ACCESS,
							   false);
}

bool
sepgsqlCheckDatabaseSuperuser(void)
{
	return checkDatabaseCommon(MyDatabaseId,
							   SEPG_DB_DATABASE__SUPERUSER,
							   false);
}

void
sepgsqlCheckDatabaseInstallModule(void)
{
	checkDatabaseCommon(MyDatabaseId,
						SEPG_DB_DATABASE__INSTALL_MODULE,
						true);
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
								   HeapTupleGetSecLabel(tuple));
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
 * sepgsqlCheckSchemaSearch
 *   checks db_schema:{search} permission when the given namespace
 *   is searched. It is not available on temporary namespace due to
 *   the limitation of implementation.
 *
 * sepgsqlCheckSchemaAddRemove
 *   checks db_schema:{add_object} and db_schema:{remove_object}
 *   permission when a database object within a certain schema
 *   is added or removed.
 */
static bool
sepgsqlCheckSchemaCommon(Oid nsid, access_vector_t required, bool abort)
{
	security_class_t	tclass;
	HeapTuple			tuple;
	bool rc;

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

bool
sepgsqlCheckSchemaSearch(Oid nsid)
{
	if (!sepgsqlIsEnabled())
		return true;

	return sepgsqlCheckSchemaCommon(nsid, SEPG_DB_SCHEMA__SEARCH, false);
}

static void
checkSchemaAddRemove(Oid nsid, bool remove)
{
	if (IsBootstrapProcessingMode() || !OidIsValid(nsid))
		return;

	sepgsqlCheckSchemaCommon(nsid, !remove
							 ? SEPG_DB_SCHEMA__ADD_OBJECT
							 : SEPG_DB_SCHEMA__REMOVE_OBJECT,
							 true);
}

#define CHECK_SCHEMA_ADD_REMOVE(catalog,member,newtup,oldtup)			\
	do {																\
		Oid nsid_new = !HeapTupleIsValid(newtup) ? InvalidOid			\
			: (((Form_##catalog) GETSTRUCT(newtup))->member);			\
		Oid nsid_old = !HeapTupleIsValid(oldtup) ? InvalidOid			\
			: (((Form_##catalog) GETSTRUCT(oldtup))->member);			\
		if (nsid_new != nsid_old)										\
		{																\
			checkSchemaAddRemove(nsid_old, true);						\
			checkSchemaAddRemove(nsid_new, false);						\
		}																\
	} while(0)

void
sepgsqlCheckSchemaAddRemove(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	switch (RelationGetRelid(rel))
	{
	case RelationRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_class,relnamespace,newtup,oldtup);
		break;
	case ConstraintRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_constraint,connamespace,newtup,oldtup);
		break;
	case ConversionRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_conversion,connamespace,newtup,oldtup);
		break;
	case OperatorClassRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_opclass,opcnamespace,newtup,oldtup);
		break;
	case OperatorRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_operator,oprnamespace,newtup,oldtup);
		break;
	case OperatorFamilyRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_opfamily,opfnamespace,newtup,oldtup);
		break;
	case ProcedureRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_proc,pronamespace,newtup,oldtup);
		break;
	case TSDictionaryRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_ts_dict,dictnamespace,newtup,oldtup);
		break;
	case TSParserRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_ts_parser,prsnamespace,newtup,oldtup);
		break;
	case TSTemplateRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_ts_template,tmplnamespace,newtup,oldtup);
		break;
	case TypeRelationId:
		CHECK_SCHEMA_ADD_REMOVE(pg_type,typnamespace,newtup,oldtup);
		break;
	default:
		/* do nothing */
		break;
	}
}

/*
 * sepgsqlCheckTableLock
 *   checks db_table:{lock} permission when the client tries to
 *   aquire explicit lock on the given relation.
 *
 * sepgsqlCheckTableTruncate
 *   checks db_table:{delete} permission when the client tries to
 *   truncate the given relation.
 *
 * sepgsqlCheckTableReference
 *   checks db_table:{reference} and db_column:{reference} permission
 *   when the client tries to set up a foreign key constraint on the
 *   certain tables and columns.
 */
static void
checkTableCommon(Oid table_oid, access_vector_t perms)
{
	security_class_t	tclass;
	HeapTuple			tuple;

	tuple = SearchSysCache(RELOID,
						   ObjectIdGetDatum(table_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for relation %u", table_oid);

	tclass = sepgsqlTupleObjectClass(RelationRelationId, tuple);
	if (tclass == SEPG_CLASS_DB_TABLE)
	{
		sepgsqlClientHasPermsTup(RelationRelationId, tuple,
								 SEPG_CLASS_DB_TABLE,
								 perms, true);
	}
	ReleaseSysCache(tuple);
}

void
sepgsqlCheckTableLock(Oid table_oid)
{
	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{lock} permission */
	checkTableCommon(table_oid, SEPG_DB_TABLE__LOCK);
}

void
sepgsqlCheckTableTruncate(Relation rel)
{
	HeapScanDesc		scan;
	HeapTuple			tuple;
	security_class_t	tclass;

	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{delete} permission */
	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__DELETE);

	/* check db_tuple:{delete} permission */
	scan = heap_beginscan(rel, SnapshotNow, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);
		sepgsqlClientHasPermsTup(RelationGetRelid(rel), tuple, tclass,
								 SEPG_DB_TUPLE__DELETE, true);
	}
	heap_endscan(scan);
}

void
sepgsqlCheckTableReference(Relation rel, int16 *attnums, int natts)
{
	HeapTuple	tuple;
	int			i;

	if (!sepgsqlIsEnabled())
		return;

	/* check db_table:{reference} permission */
	checkTableCommon(RelationGetRelid(rel), SEPG_DB_TABLE__REFERENCE);

	/* check db_column:{reference} permission */
	for (i=0; i < natts; i++)
	{
		tuple = SearchSysCache(ATTNUM,
							   RelationGetRelid(rel),
							   attnums[i], 0, 0);
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

/*
 * sepgsqlCheckSequenceGetValue
 *   checks db_sequence:{get_value} permission when the client
 *   refers the given sequence object without any increments.
 *
 * sepgsqlCheckSequenceNextValue
 *   checks db_sequence:{next_value} permission when the client
 *   fetchs a value from the given sequence object with an
 *   increment of the counter.
 *
 * sepgsqlCheckSequenceSetValue
 *   checks db_sequence:{set_value} permission when the client
 *   set a discretionary value on the given sequence object.
 */
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

/*
 * sepgsqlCheckProcedureExecute
 *   checks db_procedure:{execute} permission when the client tries
 *   to invoke the given SQL function.
 */
bool sepgsqlCheckProcedureExecute(Oid proc_oid)
{
	HeapTuple tuple;
	bool rc;

	if (!sepgsqlIsEnabled())
		return true;

	/*
	 * check db_procedure:{execute} permission
	 */
	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(proc_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "SELinux: cache lookup failed for procedure: %u", proc_oid);

	rc = sepgsqlClientHasPermsTup(ProcedureRelationId, tuple,
								  SEPG_CLASS_DB_PROCEDURE,
								  SEPG_DB_PROCEDURE__EXECUTE,
								  false);
	ReleaseSysCache(tuple);

	return rc;
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
 * sepgsqlCheckProcedureInstall
 *   checks permission: db_procedure:{install}, when client tries to modify
 *   a system catalog which contains procedure id to invoke it later.
 *   Because these functions are invoked internally, to search a table with
 *   a special index algorithm for example, the security policy has to prevent
 *   malicious user-defined functions to be installed.
 */
static void
checkProcedureInstall(Oid proc_oid)
{
	HeapTuple	tuple;

	if (!OidIsValid(proc_oid))
		return;

	/*
	 * NOTE: we assume all the function installed
	 * during bootstraping mode can be trusted.
	 */
	if (IsBootstrapProcessingMode())
		return;

	tuple = SearchSysCache(PROCOID,
						   ObjectIdGetDatum(proc_oid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		return;

	sepgsqlClientHasPermsTup(ProcedureRelationId, tuple,
							 SEPG_CLASS_DB_PROCEDURE,
							 SEPG_DB_PROCEDURE__INSTALL,
							 true);
	ReleaseSysCache(tuple);
}

#define CHECK_PROC_INSTALL_PERM(catalog,member,newtup,oldtup)			\
	do {																\
		if (!HeapTupleIsValid(oldtup))									\
			checkProcedureInstall(((Form_##catalog) GETSTRUCT(newtup))->member); \
		else if (((Form_##catalog) GETSTRUCT(newtup))->member			\
				 != ((Form_##catalog) GETSTRUCT(oldtup))->member)		\
			checkProcedureInstall(((Form_##catalog) GETSTRUCT(newtup))->member); \
	} while(0)

void
sepgsqlCheckProcedureInstall(Relation rel, HeapTuple newtup, HeapTuple oldtup)
{
	/*
	 * db_procedure:{install} check prevent a malicious functions
	 * to be installed, as a part of system catalogs.
	 * It is necessary to prevent other person implicitly to invoke
	 * malicious functions.
	 */
	switch (RelationGetRelid(rel))
	{
	case AggregateRelationId:
		/*
		 * db_procedure:{execute} is checked on invocations of:
		 *   pg_aggregate.aggfnoid
		 *   pg_aggregate.aggtransfn
		 *   pg_aggregate.aggfinalfn
		 */
		break;

	case AccessMethodRelationId:
		CHECK_PROC_INSTALL_PERM(pg_am, aminsert, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambeginscan, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amgettuple, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amgetbitmap, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amrescan, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amendscan, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ammarkpos, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amrestrpos, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambuild, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambulkdelete, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amvacuumcleanup, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amcostestimate, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amoptions, newtup, oldtup);
		break;

	case AccessMethodProcedureRelationId:
		CHECK_PROC_INSTALL_PERM(pg_amproc, amproc, newtup, oldtup);
		break;

	case CastRelationId:
		CHECK_PROC_INSTALL_PERM(pg_cast, castfunc, newtup, oldtup);
		break;

	case ConversionRelationId:
		CHECK_PROC_INSTALL_PERM(pg_conversion, conproc, newtup, oldtup);
		break;

	case ForeignDataWrapperRelationId:
		CHECK_PROC_INSTALL_PERM(pg_foreign_data_wrapper, fdwvalidator, newtup, oldtup);
		break;

	case LanguageRelationId:
		CHECK_PROC_INSTALL_PERM(pg_language, lanplcallfoid, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_language, lanvalidator, newtup, oldtup);
		break;

	case OperatorRelationId:
		CHECK_PROC_INSTALL_PERM(pg_operator, oprcode, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_operator, oprrest, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_operator, oprjoin, newtup, oldtup);
		break;

	case TriggerRelationId:
		CHECK_PROC_INSTALL_PERM(pg_trigger, tgfoid, newtup, oldtup);
		break;

	case TSParserRelationId:
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsstart, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prstoken, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsend, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsheadline, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prslextype, newtup, oldtup);
		break;

	case TSTemplateRelationId:
		CHECK_PROC_INSTALL_PERM(pg_ts_template, tmplinit, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_template, tmpllexize, newtup, oldtup);
		break;

	case TypeRelationId:
		CHECK_PROC_INSTALL_PERM(pg_type, typinput, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typoutput, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typreceive, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typsend, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typmodin, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typmodout, newtup, oldtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typanalyze, newtup, oldtup);
		break;
	}
}

/*
 * sepgsqlCheckBlobCreate
 *   assigns a default security label and checks db_blob:{create}
 */
void
sepgsqlCheckBlobCreate(Relation rel, HeapTuple lotup)
{
	if (!sepgsqlIsEnabled())
		return;

	/* set a default security context */
	sepgsqlSetDefaultSecLabel(rel, lotup);
	sepgsqlClientHasPermsTup(RelationGetRelid(rel), lotup,
							 SEPG_CLASS_DB_BLOB,
							 SEPG_DB_BLOB__CREATE,
							 true);
}

/*
 * sepgsqlCheckBlobDrop
 *   checks db_blob:{drop} permission
 */
void
sepgsqlCheckBlobDrop(Relation rel, HeapTuple lotup)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsqlClientHasPermsTup(RelationGetRelid(rel), lotup,
							 SEPG_CLASS_DB_BLOB,
							 SEPG_DB_BLOB__DROP,
							 true);
}

/*
 * sepgsqlCheckBlobRead
 *   checks db_blob:{read} permission
 */
void
sepgsqlCheckBlobRead(LargeObjectDesc *lobj)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsqlClientHasPermsSid(LargeObjectRelationId,
							 lobj->secid,
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
	if (!sepgsqlIsEnabled())
		return;

	sepgsqlClientHasPermsSid(LargeObjectRelationId,
							 lobj->secid,
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
	if (!sepgsqlIsEnabled())
		return;

	sepgsqlClientHasPermsTup(LargeObjectRelationId, tuple,
							 SEPG_CLASS_DB_BLOB,
							 SEPG_DB_BLOB__GETATTR,
							 true);
}

/*
 * sepgsqlCheckBlobSetattr
 *   check db_blob:{setattr} permission
 */
void
sepgsqlCheckBlobSetattr(HeapTuple tuple)
{
	if (!sepgsqlIsEnabled())
		return;

	sepgsqlClientHasPermsTup(LargeObjectRelationId, tuple,
							 SEPG_CLASS_DB_BLOB,
							 SEPG_DB_BLOB__SETATTR,
							 true);
}

/*
 * sepgsqlCheckBlobExport
 *   check db_blob:{read export} and file:{write} permission
 */
void
sepgsqlCheckBlobExport(LargeObjectDesc *lobj,
					   int fdesc, const char *filename)
{
	if (!sepgsqlIsEnabled())
		return;

	/* db_blob:{read export} */
	sepgsqlClientHasPermsSid(LargeObjectRelationId,
							 lobj->secid,
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
	if (!sepgsqlIsEnabled())
		return;

	/* db_blob:{write import} */
	sepgsqlClientHasPermsSid(LargeObjectRelationId,
							 lobj->secid,
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
	access_vector_t		required = SEPG_DB_BLOB__SETATTR;

	if (HeapTupleGetSecLabel(oldtup) != HeapTupleGetSecLabel(newtup))
		required |= SEPG_DB_BLOB__RELABELFROM;

	sepgsqlClientHasPermsTup(LargeObjectRelationId, oldtup,
							 SEPG_CLASS_DB_BLOB,
							 required,
							 true);
	if ((required & SEPG_DB_BLOB__RELABELFROM) == 0)
		return;

	sepgsqlClientHasPermsTup(LargeObjectRelationId, newtup,
							 SEPG_CLASS_DB_BLOB,
							 SEPG_DB_BLOB__RELABELTO,
							 true);
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
