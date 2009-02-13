/*
 * src/backend/security/sepgsql/permissions.c
 *	 applies SE-PostgreSQL permission checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/genam.h"
#include "catalog/indexing.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_am.h"
#include "catalog/pg_amproc.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_class.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_database.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_security.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/pgace.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "utils/tqual.h"

/*
 * It can be configured via a GUC variable to toggle
 * row-level access controls.
 */
bool sepostgresql_row_level;

/*
 * sepgsqlTupleName
 *   returns an identifier string to generate audit record for
 *   the given tuple. Please note that its results can indicate
 *   an address within the given tuple, so we should not refer
 *   the returned pointer after HeapTuple is released.
 */
const char *
sepgsqlTupleName(Oid relid, HeapTuple tuple)
{
	static char buffer[NAMEDATALEN * 2 + 10];

	switch (relid)
	{
	case DatabaseRelationId:
		return NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname);

	case RelationRelationId:
		return NameStr(((Form_pg_class) GETSTRUCT(tuple))->relname);

	case AttributeRelationId:
		if (!IsBootstrapProcessingMode())
		{
			Form_pg_attribute attForm
				= (Form_pg_attribute) GETSTRUCT(tuple);
			char *relname
				= get_rel_name(attForm->attrelid);

			if (relname)
			{
				snprintf(buffer, sizeof(buffer), "%s.%s",
						 relname, NameStr(attForm->attname));
				pfree(relname);
				return buffer;
			}
		}
		return NameStr(((Form_pg_attribute) GETSTRUCT(tuple))->attname);

	case ProcedureRelationId:
		return NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname);

	case LargeObjectRelationId:
		snprintf(buffer, sizeof(buffer), "loid:%u",
				 ((Form_pg_largeobject) GETSTRUCT(tuple))->loid);
		return buffer;
	}
	return NULL;	/* No tuple name for audit record */
}

/*
 * sepgsqlFileObjectClass
 *
 * It returns proper object class of filesystem object already opened.
 * It is necessary to check privileges voluntarily.
 */
security_class_t
sepgsqlFileObjectClass(int fdesc, const char *filename)
{
	struct stat stbuf;

	if (fstat(fdesc, &stbuf) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not stat file \"%s\": %m", filename)));

	if (S_ISDIR(stbuf.st_mode))
		return SECCLASS_DIR;
	else if (S_ISCHR(stbuf.st_mode))
		return SECCLASS_CHR_FILE;
	else if (S_ISBLK(stbuf.st_mode))
		return SECCLASS_BLK_FILE;
	else if (S_ISFIFO(stbuf.st_mode))
		return SECCLASS_FIFO_FILE;
	else if (S_ISLNK(stbuf.st_mode))
		return SECCLASS_LNK_FILE;
	else if (S_ISSOCK(stbuf.st_mode))
		return SECCLASS_SOCK_FILE;

	return SECCLASS_FILE;
}

/*
 * sepgsqlTupleObjectClass
 *
 * It returns proper object class of given tuple
 */
security_class_t
sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple)
{
	Form_pg_class clsForm;
	Form_pg_attribute attForm;

	switch (relid)
	{
		case DatabaseRelationId:
			return SECCLASS_DB_DATABASE;

		case RelationRelationId:
			clsForm = (Form_pg_class) GETSTRUCT(tuple);
			if (clsForm->relkind == RELKIND_RELATION)
				return SECCLASS_DB_TABLE;
			break;

		case AttributeRelationId:
			attForm = (Form_pg_attribute) GETSTRUCT(tuple);
			if (attForm->attkind == RELKIND_RELATION)
				return SECCLASS_DB_COLUMN;
			break;

		case ProcedureRelationId:
			return SECCLASS_DB_PROCEDURE;

		case LargeObjectRelationId:
			return SECCLASS_DB_BLOB;
	}

	return SECCLASS_DB_TUPLE;
}

/*
 * sepgsqlCheckTuplePerms 
 *
 * This function evaluates given permission set (SEPGSQL_PERMS_*) onto the
 * given tuple, with translating them into proper SELinux permission.
 *  
 * Accesses to some of system catalog has special meanings. DELETE a tuple
 * within pg_class also means DROP TABLE for instance. In this case,
 * SE-PostgreSQL translate given SEPGSQL_PERMS_DELETE into DB_TABLE__DROP
 * to keep consistency of user operation. To delete a tuple within pg_class
 * always means dropping a table independent from what SQL statement is
 * used.
 *
 * Thus, checks for some of system catalog need to modify given permission
 * set at checkTuplePermsXXXX() functions.
 */
static access_vector_t
sepgsqlPermsToCommonAv(uint32 perms)
{
	access_vector_t result = 0;

	result |= (perms & SEPGSQL_PERMS_USE         ? COMMON_DATABASE__GETATTR : 0);
	result |= (perms & SEPGSQL_PERMS_SELECT      ? COMMON_DATABASE__GETATTR : 0);
	result |= (perms & SEPGSQL_PERMS_UPDATE      ? COMMON_DATABASE__SETATTR : 0);
	result |= (perms & SEPGSQL_PERMS_INSERT      ? COMMON_DATABASE__CREATE : 0);
	result |= (perms & SEPGSQL_PERMS_DELETE      ? COMMON_DATABASE__DROP : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELFROM ? COMMON_DATABASE__RELABELFROM : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELTO   ? COMMON_DATABASE__RELABELTO : 0);

	return result;
}

static access_vector_t
sepgsqlPermsToDatabaseAv(uint32 perms, HeapTuple tuple, HeapTuple newtup)
{
	return sepgsqlPermsToCommonAv(perms);
}

static access_vector_t
sepgsqlPermsToTableAv(uint32 perms, HeapTuple tuple, HeapTuple newtup)
{
	return sepgsqlPermsToCommonAv(perms);
}

static access_vector_t
sepgsqlPermsToProcedureAv(uint32 perms, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t result = sepgsqlPermsToCommonAv(perms);
	Form_pg_proc proForm;
	HeapTuple protup;
	Datum probin;
	bool isnull;

	/*
	 * Check permission for loadable module installation
	 */
	protup = HeapTupleIsValid(newtup) ? newtup : tuple;
	proForm = (Form_pg_proc) GETSTRUCT(protup);

	if (proForm->prolang == ClanguageId)
	{
		bool need_check = false;

		probin = SysCacheGetAttr(PROCOID, protup,
								 Anum_pg_proc_probin,
								 &isnull);
		if (!isnull)
		{
			if (result & DB_PROCEDURE__CREATE)
				need_check = true;
			else if (HeapTupleIsValid(newtup))
			{
				Form_pg_proc oldForm = (Form_pg_proc) GETSTRUCT(tuple);

				if (oldForm->prolang != proForm->prolang)
					need_check = true;
				else
				{
					Datum oldbin = SysCacheGetAttr(PROCOID, tuple,
												   Anum_pg_proc_probin,
												   &isnull);
					if (isnull)
						need_check = true;
					else
					{
						Datum comp = DirectFunctionCall2(byteane, oldbin, probin);
						need_check = DatumGetBool(comp);
					}
				}
			}

			if (need_check)
			{
				char *filename = TextDatumGetCString(probin);

				sepgsqlCheckModuleInstallPerms(filename);
			}
		}
	}

	return result;
}

static access_vector_t
sepgsqlPermsToColumnAv(uint32 perms, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t result = sepgsqlPermsToCommonAv(perms);

	if (HeapTupleIsValid(newtup))
	{
		Form_pg_attribute oldatt = (Form_pg_attribute) GETSTRUCT(tuple);
		Form_pg_attribute newatt = (Form_pg_attribute) GETSTRUCT(newtup);

		if (!oldatt->attisdropped && newatt->attisdropped)
			result |= DB_COLUMN__DROP;
		if (oldatt->attisdropped && !newatt->attisdropped)
			result |= DB_COLUMN__CREATE;
	}
	return result;
}

static access_vector_t
sepgsqlPermsToTupleAv(uint32 perms, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t result = 0;

	result |= (perms & SEPGSQL_PERMS_USE         ? DB_TUPLE__USE : 0);
	result |= (perms & SEPGSQL_PERMS_SELECT      ? DB_TUPLE__SELECT : 0);
	result |= (perms & SEPGSQL_PERMS_UPDATE      ? DB_TUPLE__UPDATE : 0);
	result |= (perms & SEPGSQL_PERMS_INSERT      ? DB_TUPLE__INSERT : 0);
	result |= (perms & SEPGSQL_PERMS_DELETE      ? DB_TUPLE__DELETE : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELFROM ? DB_TUPLE__RELABELFROM : 0);
	result |= (perms & SEPGSQL_PERMS_RELABELTO   ? DB_TUPLE__RELABELTO : 0);

	return result;
}

static access_vector_t
sepgsqlPermsToBlobAv(uint32 perms, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t result = sepgsqlPermsToCommonAv(perms);

	/*
	 * NOTE: INSERT tuples into pg_largeobject has a possibility to create
	 * a new largeobject, if the given loid is not exist on the current
	 * pg_largeobject. Ditto for DELETE statement, it also has a possibility
	 * to drop a largeobject, if it removes all tuples within a large object.
	 *
	 * UPDATE pg_largeobject.loid has a possibility to create and drop
	 * a largeobject in same time, so we need to check it when loid is
	 * changed.
	 *
	 * db_blob:{create} and db_blob:{drop} should be evaluated for
	 * creation/deletion of largeobject, but we have to check pg_largeobject
	 * with SnapshotSelf whether there is one or more tuple having same loid,
	 * or not, on each tuple insertion or deletion.
	 *
	 * So, we assume any INSERT means db_blob:{create}, any DELETE means
	 * db_blob:{drop}.
	 */
	result |= (perms & SEPGSQL_PERMS_INSERT	? DB_BLOB__WRITE : 0);
	if (perms & SEPGSQL_PERMS_UPDATE)
	{
		result |= DB_BLOB__WRITE;

		if (((Form_pg_largeobject) GETSTRUCT(tuple))->loid !=
			((Form_pg_largeobject) GETSTRUCT(newtup))->loid)
			result |= (DB_BLOB__CREATE | DB_BLOB__DROP);
	}
	result |= (perms & SEPGSQL_PERMS_DELETE	? DB_BLOB__WRITE : 0);
	result |= (perms & SEPGSQL_PERMS_READ	? DB_BLOB__READ  : 0);

	return result;
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
	if (!OidIsValid(proc_oid))
		return;

	if (IsBootstrapProcessingMode())
	{
		/*
		 * We assume all procedures have same security context
		 * in bootstrap processing mode, because no one can
		 * relabel it.
		 */
		Oid proc_sid
			= sepgsqlClientCreateSid(sepgsqlGetDatabaseSecurityId(),
									 SECCLASS_DB_PROCEDURE);
		sepgsqlClientHasPermission(proc_sid,
								   SECCLASS_DB_PROCEDURE,
								   DB_PROCEDURE__INSTALL,
								   NULL);
	}
	else
	{
		HeapTuple protup;
		const char *audit_name;

		protup = SearchSysCache(PROCOID,
								ObjectIdGetDatum(proc_oid),
								0, 0, 0);
		if (!HeapTupleIsValid(protup))
			return;

		audit_name = sepgsqlTupleName(ProcedureRelationId, protup);
		sepgsqlClientHasPermission(HeapTupleGetSecLabel(protup),
								   SECCLASS_DB_PROCEDURE,
								   DB_PROCEDURE__INSTALL,
								   audit_name);
		ReleaseSysCache(protup);
	}
}

#define CHECK_PROC_INSTALL_HANDLER(catalog,member,tuple,newtup)			\
	do {																\
		if (!HeapTupleIsValid(newtup))									\
			checkProcedureInstall(((CppConcat(Form_,catalog)) GETSTRUCT(tuple))->member); \
		else if (((CppConcat(Form_,catalog)) GETSTRUCT(tuple))->member	\
				 != ((CppConcat(Form_,catalog)) GETSTRUCT(newtup))->member) \
			checkProcedureInstall(((CppConcat(Form_,catalog)) GETSTRUCT(newtup))->member); \
	} while(0)

static void
sepgsqlCheckProcedureInstall(Relation rel, HeapTuple tuple, HeapTuple newtup)
{
	/*
	 * Some of system catalog can be configured to invoke functions
	 * implicitly. It checks permission to prevent implicit invocation
	 * of malicious functions.
	 */
	switch (RelationGetRelid(rel))
	{
	case AggregateRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_aggregate, aggfnoid, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_aggregate, aggtransfn, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_aggregate, aggfinalfn, tuple, newtup);
		break;

	case AccessMethodRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_am, aminsert, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, ambeginscan, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amgettuple, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amgetbitmap, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amrescan, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amendscan, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, ammarkpos, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amrestrpos, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, ambuild, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, ambulkdelete, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amvacuumcleanup, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amcostestimate, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_am, amoptions, tuple, newtup);
		break;

	case AccessMethodProcedureRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_amproc, amproc, tuple, newtup);
		break;

	case CastRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_cast, castfunc, tuple, newtup);
		break;

	case ConversionRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_conversion, conproc, tuple, newtup);
		break;

	case LanguageRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_language, lanplcallfoid, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_language, lanvalidator, tuple, newtup);
		break;

	case OperatorRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_operator, oprcode, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_operator, oprrest, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_operator, oprjoin, tuple, newtup);
		break;

	case TriggerRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_trigger, tgfoid, tuple, newtup);
		break;

	case TSParserRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_ts_parser, prsstart, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_ts_parser, prstoken, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_ts_parser, prsend, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_ts_parser, prsheadline, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_ts_parser, prslextype, tuple, newtup);
		break;

	case TSTemplateRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_ts_template, tmplinit, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_ts_template, tmpllexize, tuple, newtup);
		break;

	case TypeRelationId:
		CHECK_PROC_INSTALL_HANDLER(pg_type, typinput, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_type, typoutput, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_type, typreceive, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_type, typsend, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_type, typmodin, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_type, typmodout, tuple, newtup);
		CHECK_PROC_INSTALL_HANDLER(pg_type, typanalyze, tuple, newtup);
		break;
	}
}

bool
sepgsqlCheckTuplePerms(Relation rel, HeapTuple tuple, HeapTuple newtup,
					   uint32 perms, bool abort)
{
	security_class_t tclass;
	access_vector_t av = 0;
	bool rc = true;

	Assert(HeapTupleIsValid(tuple));

	if ((perms & (SEPGSQL_PERMS_INSERT | SEPGSQL_PERMS_UPDATE)) != 0)
		sepgsqlCheckProcedureInstall(rel, tuple, newtup);

	tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);

	switch (tclass)
	{
		case SECCLASS_DB_DATABASE:
			av = sepgsqlPermsToDatabaseAv(perms, tuple, newtup);
			break;

		case SECCLASS_DB_TABLE:
			av = sepgsqlPermsToTableAv(perms, tuple, newtup);
			break;

		case SECCLASS_DB_PROCEDURE:
			av = sepgsqlPermsToProcedureAv(perms, tuple, newtup);
			break;

		case SECCLASS_DB_COLUMN:
			av = sepgsqlPermsToColumnAv(perms, tuple, newtup);
			break;

		case SECCLASS_DB_BLOB:
			av = sepgsqlPermsToBlobAv(perms, tuple, newtup);
			break;

		default: /* SECCLASS_DB_TUPLE */
			if (sepostgresql_row_level)
				av = sepgsqlPermsToTupleAv(perms, tuple, newtup);
			break;
	}

	if (av)
	{
		const char *audit_name
			= sepgsqlTupleName(RelationGetRelid(rel), tuple);

		if (abort)
		{
			sepgsqlClientHasPermission(HeapTupleGetSecLabel(tuple),
									   tclass, av, audit_name);
		}
		else
		{
			rc = sepgsqlClientHasPermissionNoAbort(HeapTupleGetSecLabel(tuple),
												   tclass, av, audit_name);
		}
	}

	return rc;
}

/*
 * sepgsqlCheckModuleInstallPerms
 *
 * It checks client's privilege to install a new shared loadable file.
 */
void
sepgsqlCheckModuleInstallPerms(const char *filename)
{
	security_context_t file_context;
	Form_pg_database dbform;
	HeapTuple dbtup;
	char *fullpath;

	/* (client) <-- db_database:module_install --> (database) */
	dbtup = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(MyDatabaseId),
						   0, 0, 0);
	if (!HeapTupleIsValid(dbtup))
		elog(ERROR, "SELinux: cache lookup failed for database: %u", MyDatabaseId);

	dbform = (Form_pg_database) GETSTRUCT(dbtup);
	sepgsqlClientHasPermission(HeapTupleGetSecLabel(dbtup),
							   SECCLASS_DB_DATABASE,
							   DB_DATABASE__INSTALL_MODULE,
							   NameStr(dbform->datname));
	ReleaseSysCache(dbtup);

	/* (client) <-- db_databse:module_install --> (*.so file) */
	fullpath = expand_dynamic_library_name(filename);
	if (getfilecon_raw(fullpath, &file_context) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not access file \"%s\": %m", fullpath)));
	PG_TRY();
	{
		sepgsqlComputePermission(sepgsqlGetClientContext(),
								 file_context,
								 SECCLASS_DB_DATABASE,
								 DB_DATABASE__INSTALL_MODULE,
								 fullpath);
	}
	PG_CATCH();
	{
		freecon(file_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(file_context);
}

/*
 * sepgsqlSetDefaultContext
 *
 * This function attach a proper security context for a newly inserted tuple,
 * refering the security policy.
 * In the default, any tuple inherits the security context of its table.
 * However, we have several exception for some of system catalog. It come from
 * TYPE_TRANSITION rules in the security policy.
 */
static Oid
sepgsqlDefaultDatabaseContext(Relation rel, HeapTuple tuple)
{
	security_context_t newcon;

	newcon = sepgsqlComputeCreateContext(sepgsqlGetClientContext(),
										 sepgsqlGetClientContext(),
										 SECCLASS_DB_DATABASE);
	return pgaceSecurityLabelToSid(newcon);
}

static Oid
sepgsqlDefaultTableContext(Relation rel, HeapTuple tuple)
{
	return sepgsqlClientCreateSid(sepgsqlGetDatabaseSecurityId(),
								  SECCLASS_DB_TABLE);
}

static Oid
sepgsqlDefaultProcedureContext(Relation rel, HeapTuple tuple)
{
	return sepgsqlClientCreateSid(sepgsqlGetDatabaseSecurityId(),
								  SECCLASS_DB_PROCEDURE);
}

static Oid
sepgsqlDefaultColumnContext(Relation rel, HeapTuple tuple)
{
	Form_pg_attribute attForm;
	Oid tblsid;

	attForm = (Form_pg_attribute) GETSTRUCT(tuple);

	if (IsBootstrapProcessingMode() &&
		(attForm->attrelid == TypeRelationId ||
		 attForm->attrelid == ProcedureRelationId ||
		 attForm->attrelid == AttributeRelationId ||
		 attForm->attrelid == RelationRelationId))
	{
		/*
		 * We cannot access relation caches on very early phase
		 * in bootstrap, so it assumes tables has default security
		 * context and unlabeled by initdb.
		 */
		tblsid = sepgsqlClientCreateSid(sepgsqlGetDatabaseSecurityId(),
										SECCLASS_DB_TABLE);
	}
	else
	{
		HeapTuple reltup
			= SearchSysCache(RELOID,
							 ObjectIdGetDatum(attForm->attrelid),
							 0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "SELinux: cache lookup failed for relation: %u",
				 attForm->attrelid);

		tblsid = HeapTupleGetSecLabel(reltup);

		ReleaseSysCache(reltup);
	}

	return sepgsqlClientCreateSid(tblsid, SECCLASS_DB_COLUMN);
}
		
static Oid
sepgsqlDefaultTupleContext(Relation rel, HeapTuple tuple)
{
	Oid tblsid;

	if (IsBootstrapProcessingMode() &&
		(RelationGetRelid(rel) == TypeRelationId ||
		 RelationGetRelid(rel) == ProcedureRelationId ||
		 RelationGetRelid(rel) == AttributeRelationId ||
		 RelationGetRelid(rel) == RelationRelationId))
	{
		/*
		 * We cannot access relation caches on very early phase
		 * in bootstrap, so it assumes tables has default security
		 * context and unlabeled by initdb.
		 */
		tblsid = sepgsqlClientCreateSid(sepgsqlGetDatabaseSecurityId(),
										SECCLASS_DB_TABLE);
	}
	else
	{
		HeapTuple reltup
			= SearchSysCache(RELOID,
							 ObjectIdGetDatum(RelationGetRelid(rel)),
							 0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "SELinux: cache lookup failed for relation: %u",
				 RelationGetRelid(rel));

		tblsid = HeapTupleGetSecLabel(reltup);

		ReleaseSysCache(reltup);
	}

	return sepgsqlClientCreateSid(tblsid, SECCLASS_DB_TUPLE);
}

static Oid
sepgsqlDefaultBlobContext(Relation rel, HeapTuple tuple)
{
	/*
	 * NOTE:
	 * A new tuple to be inserted into pg_largeobject inherits
	 * a security context of prior tuples of same large object.
	 * The "SnapshotNow" is available for this purpose because
	 * lo_create() invokes CommandCounterIncrement() just after
	 * creation of a new large object.
	 *
	 * If we can find no prior tuples, it means this action to
	 * insert the first page, or client invokes INSERT INTO ...
	 * with multiple tuples with same loid. However, these
	 * tuples are labeled by same TYPE_TRANSITION rules in both
	 * cases. So, there are no differences.
	 */
	Form_pg_largeobject loForm
		= (Form_pg_largeobject) GETSTRUCT(tuple);
	ScanKeyData		skey;
	SysScanDesc		scan;
	HeapTuple		lotup;
	Oid				newsid = InvalidOid;

	ScanKeyInit(&skey,
				Anum_pg_largeobject_loid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(loForm->loid));
	scan = systable_beginscan(rel,
							  LargeObjectLOidPNIndexId, true,
							  SnapshotNow, 1, &skey);
	while ((lotup = systable_getnext(scan)) != NULL)
	{
		newsid = HeapTupleGetSecLabel(lotup);
		if (OidIsValid(newsid))
			break;
	}
	systable_endscan(scan);

	if (!OidIsValid(newsid))
	{
		newsid = sepgsqlClientCreateSid(sepgsqlGetDatabaseSecurityId(),
										SECCLASS_DB_BLOB);
	}

	return newsid;
}

void
sepgsqlSetDefaultContext(Relation rel, HeapTuple tuple)
{
	security_class_t tclass;
	Oid newsid;

	Assert(HeapTupleHasSecLabel(tuple));
	tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);

	switch (tclass)
	{
		case SECCLASS_DB_DATABASE:
			newsid = sepgsqlDefaultDatabaseContext(rel, tuple);
			break;
		case SECCLASS_DB_TABLE:
			newsid = sepgsqlDefaultTableContext(rel, tuple);
			break;
		case SECCLASS_DB_PROCEDURE:
			newsid = sepgsqlDefaultProcedureContext(rel, tuple);
			break;
		case SECCLASS_DB_COLUMN:
			newsid = sepgsqlDefaultColumnContext(rel, tuple);
			break;
		case SECCLASS_DB_BLOB:
			newsid = sepgsqlDefaultBlobContext(rel, tuple);
			break;
		default: /* SECCLASS_DB_TUPLE */
			newsid = sepgsqlDefaultTupleContext(rel, tuple);
			break;
	}

	HeapTupleSetSecLabel(tuple, newsid);
}