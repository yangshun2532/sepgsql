/*
 * src/backend/utils/sepgsql/perms.c
 *   SE-PostgreSQL permission checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

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
#include "catalog/pg_trigger.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/sepgsql.h"
#include "utils/syscache.h"

/*
 * sepgsqlAuditName
 *   returns an identifier string to generate audit record for
 *   the given tuple. Please note that its results can indicate
 *   an address within the given tuple, so we should not refer
 *   the returned pointer after HeapTuple is released.
 */
const char *
sepgsqlAuditName(Oid relid, HeapTuple tuple)
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
	}
	return NULL;
}

/*
 * sepgsqlFileObjectClass
 *
 * It returns proper object class of filesystem object already opened.
 * It is necessary to check privileges voluntarily.
 */
security_class_t
sepgsqlFileObjectClass(int fdesc)
{
	struct stat stbuf;

	if (fstat(fdesc, &stbuf) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not stat file descriptor: %d", fdesc)));

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
 * It returns correct object class of given tuple
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
	sepgsql_sid_t	prosid;
	HeapTuple		protup = NULL;
	const char	   *audit_name = NULL;

	if (!OidIsValid(proc_oid))
		return;

	if (IsBootstrapProcessingMode())
	{
		/*
		 * Assumption: security label is unchanged
		 * during bootstraptin mode, because no one
		 * tries to relabel anything.
		 */
		prosid  = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
									  SECCLASS_DB_PROCEDURE);
	}
	else
	{
		protup = SearchSysCache(PROCOID,
								ObjectIdGetDatum(proc_oid),
								0, 0, 0);
		if (!HeapTupleIsValid(protup))
			return;

		audit_name = sepgsqlAuditName(ProcedureRelationId, protup);
		prosid = HeapTupleGetSecLabel(ProcedureRelationId, protup);
	}

	sepgsqlClientHasPerms(prosid,
						  SECCLASS_DB_PROCEDURE,
						  DB_PROCEDURE__INSTALL,
						  audit_name, true);
	if (HeapTupleIsValid(protup))
		ReleaseSysCache(protup);
}

#define CHECK_PROC_INSTALL_PERM(catalog,member,tuple,newtup)			\
	do {                                                                \
		if (!HeapTupleIsValid(newtup))                                  \
			checkProcedureInstall(((CppConcat(Form_,catalog)) GETSTRUCT(tuple))->member); \
		else if (((CppConcat(Form_,catalog)) GETSTRUCT(tuple))->member != \
				 ((CppConcat(Form_,catalog)) GETSTRUCT(newtup))->member) \
			checkProcedureInstall(((CppConcat(Form_,catalog)) GETSTRUCT(newtup))->member); \
	} while(0)

static void
sepgsqlCheckProcedureInstall(Relation rel, HeapTuple tuple, HeapTuple newtup)
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
		CHECK_PROC_INSTALL_PERM(pg_aggregate, aggfnoid, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_aggregate, aggtransfn, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_aggregate, aggfinalfn, tuple, newtup);
		break;

	case AccessMethodRelationId:
		CHECK_PROC_INSTALL_PERM(pg_am, aminsert, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambeginscan, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amgettuple, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amgetbitmap, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amrescan, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amendscan, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ammarkpos, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amrestrpos, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambuild, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, ambulkdelete, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amvacuumcleanup, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amcostestimate, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_am, amoptions, tuple, newtup);
		break;

	case AccessMethodProcedureRelationId:
		CHECK_PROC_INSTALL_PERM(pg_amproc, amproc, tuple, newtup);
		break;

	case CastRelationId:
		CHECK_PROC_INSTALL_PERM(pg_cast, castfunc, tuple, newtup);
		break;

	case ConversionRelationId:
		CHECK_PROC_INSTALL_PERM(pg_conversion, conproc, tuple, newtup);
		break;

	case LanguageRelationId:
		CHECK_PROC_INSTALL_PERM(pg_language, lanplcallfoid, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_language, lanvalidator, tuple, newtup);
		break;

	case OperatorRelationId:
		CHECK_PROC_INSTALL_PERM(pg_operator, oprcode, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_operator, oprrest, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_operator, oprjoin, tuple, newtup);
		break;

	case TriggerRelationId:
		CHECK_PROC_INSTALL_PERM(pg_trigger, tgfoid, tuple, newtup);
		break;

	case TSParserRelationId:
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsstart, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prstoken, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsend, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prsheadline, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_parser, prslextype, tuple, newtup);
		break;

	case TSTemplateRelationId:
		CHECK_PROC_INSTALL_PERM(pg_ts_template, tmplinit, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_ts_template, tmpllexize, tuple, newtup);
		break;

	case TypeRelationId:
		CHECK_PROC_INSTALL_PERM(pg_type, typinput, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typoutput, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typreceive, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typsend, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typmodin, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typmodout, tuple, newtup);
		CHECK_PROC_INSTALL_PERM(pg_type, typanalyze, tuple, newtup);
		break;
	}
}

/*
 * sepgsqlxxxxAvPerms
 *    translate generic required permissions into per object
 *    class permission bits.
 */
static access_vector_t
sepgsqlCommonAvPerms(uint32 required)
{
	access_vector_t av_perms = 0;

	av_perms |= (required & SEPGSQL_PERMS_USE
				 ? COMMON_DATABASE__GETATTR : 0);
	av_perms |= (required & SEPGSQL_PERMS_SELECT
				 ? COMMON_DATABASE__GETATTR : 0);
	av_perms |= (required & SEPGSQL_PERMS_UPDATE
				 ? COMMON_DATABASE__SETATTR : 0);
	av_perms |= (required & SEPGSQL_PERMS_INSERT
				 ? COMMON_DATABASE__CREATE : 0);
	av_perms |= (required & SEPGSQL_PERMS_DELETE
				 ? COMMON_DATABASE__DROP : 0);
	av_perms |= (required & SEPGSQL_PERMS_RELABELFROM
				 ? COMMON_DATABASE__RELABELFROM : 0);
	av_perms |= (required & SEPGSQL_PERMS_RELABELTO
				 ? COMMON_DATABASE__RELABELTO : 0);
	return av_perms;
}

static access_vector_t
sepgsqlDatabaseAvPerms(uint32 required, HeapTuple tuple, HeapTuple newtup)
{
	return sepgsqlCommonAvPerms(required);
}

static access_vector_t
sepgsqlTableAvPerms(uint32 required, HeapTuple tuple, HeapTuple newtup)
{
	return sepgsqlCommonAvPerms(required);
}

static access_vector_t
sepgsqlColumnAvPerms(uint32 required, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t av_perms = sepgsqlCommonAvPerms(required);

	if (HeapTupleIsValid(newtup))
	{
		Form_pg_attribute oldatt = (Form_pg_attribute) GETSTRUCT(tuple);
		Form_pg_attribute newatt = (Form_pg_attribute) GETSTRUCT(newtup);

		if (!oldatt->attisdropped && newatt->attisdropped)
			av_perms |= DB_COLUMN__DROP;
		if (oldatt->attisdropped && !newatt->attisdropped)
			av_perms |= DB_COLUMN__CREATE;
	}

	return av_perms;
}

static access_vector_t
sepgsqlProcedureAvPerms(uint32 required, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t av_perms = sepgsqlCommonAvPerms(required);
	Form_pg_proc proForm;
	Form_pg_proc oldForm;
	char *filename = NULL;
	Datum probin;
	Datum oldbin;
	bool isnull;

	/*
	 * check permission for loadable module installation
	 */
	if (HeapTupleIsValid(newtup))
	{
		Assert(required & SEPGSQL_PERMS_UPDATE);

		proForm = (Form_pg_proc) GETSTRUCT(newtup);
		oldForm = (Form_pg_proc) GETSTRUCT(tuple);
		probin = SysCacheGetAttr(PROCOID, newtup,
								 Anum_pg_proc_probin,
								 &isnull);
		if (!isnull)
		{
			oldbin = SysCacheGetAttr(PROCOID, tuple,
									 Anum_pg_proc_probin,
									 &isnull);
			if (isnull ||
				oldForm->prolang != proForm->prolang ||
				DatumGetBool(DirectFunctionCall2(byteane, oldbin, probin)))
			{
				filename = TextDatumGetCString(probin);
				sepgsqlCheckDatabaseInstallModule(filename);
			}
		}
	}
	else if (required & SEPGSQL_PERMS_INSERT)
	{
		proForm = (Form_pg_proc) GETSTRUCT(tuple);

		if (proForm->prolang == ClanguageId)
		{
			probin = SysCacheGetAttr(PROCOID, tuple,
									 Anum_pg_proc_probin,
									 &isnull);
			if (!isnull)
			{
				filename = TextDatumGetCString(probin);
				sepgsqlCheckDatabaseInstallModule(filename);
			}
		}
	}

	return av_perms;
}

/*
 * sepgsqlCheckObjectPerms
 *   checks permission of the given object (tuple).
 */
bool
sepgsqlCheckObjectPerms(Relation rel, HeapTuple tuple, HeapTuple newtup,
						uint32 required, bool abort)
{
	Oid relid = RelationGetRelid(rel);
	sepgsql_sid_t		sid;
	security_class_t	tclass;
	access_vector_t		av_perms;
	const char		   *audit_name;
	bool				rc = true;

	Assert(HeapTupleIsValid(tuple));
	Assert(!HeapTupleIsValid(newtup) ||
		   (required & SEPGSQL_PERMS_UPDATE));

	if (required & (SEPGSQL_PERMS_INSERT | SEPGSQL_PERMS_UPDATE))
		sepgsqlCheckProcedureInstall(rel, tuple, newtup);

	tclass = sepgsqlTupleObjectClass(relid, tuple);
	switch (tclass)
	{
	case SECCLASS_DB_DATABASE:
		av_perms = sepgsqlDatabaseAvPerms(required, tuple, newtup);
		break;
	case SECCLASS_DB_TABLE:
		av_perms = sepgsqlTableAvPerms(required, tuple, newtup);
		break;
	case SECCLASS_DB_COLUMN:
		av_perms = sepgsqlColumnAvPerms(required, tuple, newtup);
		break;
	case SECCLASS_DB_PROCEDURE:
		av_perms = sepgsqlProcedureAvPerms(required, tuple, newtup);
		break;
	default:
		/*
		 * Currently, row-level access control is not
		 * implement, so it skipps all the checks on
		 * db_tuple class obejcts.
		 */
		av_perms = 0;
		break;
	}
	if (av_perms)
	{
		audit_name = sepgsqlAuditName(relid, tuple);
		sid = HeapTupleGetSecLabel(relid, tuple);
		rc = sepgsqlClientHasPerms(sid, tclass, av_perms,
								   audit_name, abort);
	}
	return rc;
}
