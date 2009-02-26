/*
 * src/backend/utils/sepgsql/perms.c
 *   SE-PostgreSQL permission checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/htup.h"
#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_security.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
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

static access_vector_t
sepgsqlBlobAvPerms(uint32 required, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t av_perms = 0;

	// TO BE IMPLEMENTED LATER

	return av_perms;
}

static access_vector_t
sepgsqlTupleAvPerms(uint32 required, HeapTuple tuple, HeapTuple newtup)
{
	access_vector_t av_perms = 0;

	av_perms |= (required & SEPGSQL_PERMS_USE
				 ? DB_TUPLE__USE : 0);
	av_perms |= (required & SEPGSQL_PERMS_SELECT
				 ? DB_TUPLE__SELECT : 0);
	av_perms |= (required & SEPGSQL_PERMS_UPDATE
				 ? DB_TUPLE__UPDATE : 0);
	av_perms |= (required & SEPGSQL_PERMS_INSERT
				 ? DB_TUPLE__INSERT : 0);
	av_perms |= (required & SEPGSQL_PERMS_DELETE
				 ? DB_TUPLE__DELETE : 0);
	av_perms |= (required & SEPGSQL_PERMS_RELABELFROM
				 ? DB_TUPLE__RELABELFROM : 0);
	av_perms |= (required & SEPGSQL_PERMS_RELABELTO
				 ? DB_TUPLE__RELABELTO : 0);

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
	security_class_t	tclass;
	access_vector_t		av_perms;
	const char		   *audit_name;
	bool				rc = true;

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
	case SECCLASS_DB_BLOB:
		av_perms = sepgsqlBlobAvPerms(required, tuple, newtup);
		break;
	default:
		av_perms = (sepostgresql_row_level ?
					sepgsqlTupleAvPerms(required, tuple, newtup) : 0);
		break;
	}
	if (av_perms)
	{
		audit_name = sepgsqlAuditName(relid, tuple);
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(tuple),
								   tclass, av_perms,
								   audit_name, abort);
	}
	return rc;
}

/*
 * sepgsqlSetDefaultSecLabel
 *
 * This function attach a correct security label for a newly created tuple
 * according to the security policy.
 * In the default, any tuple inherits the security context of its table.
 * However, we have several exception for some of system catalog. It come from
 * TYPE_TRANSITION rules in the security policy.
 */
static sepgsql_sid_t
defaultDatabaseSecLabel(Relation rel, HeapTuple tuple)
{
	security_context_t	newcon;

	newcon = sepgsqlComputeCreate(sepgsqlGetClientLabel(),
								  sepgsqlGetClientLabel(),
								  SECCLASS_DB_DATABASE);
	return securityTransSecLabelIn(newcon);
}

static sepgsql_sid_t
defaultTableSecLabel(Relation rel, HeapTuple tuple)
{
	return sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
							   SECCLASS_DB_TABLE);
}

static sepgsql_sid_t
defaultProcedureSecLabel(Relation rel, HeapTuple tuple)
{
	return sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
							   SECCLASS_DB_PROCEDURE);
}

static sepgsql_sid_t
defaultColumnSecLabel(Relation rel, HeapTuple tuple)
{
	Form_pg_attribute	attForm;
	HeapTuple			reltup;
	sepgsql_sid_t		relsid;

	attForm = (Form_pg_attribute) GETSTRUCT(tuple);

	if (IsBootstrapProcessingMode() &&
		(attForm->attrelid == TypeRelationId ||
		 attForm->attrelid == ProcedureRelationId ||
		 attForm->attrelid == AttributeRelationId ||
		 attForm->attrelid == RelationRelationId))
	{
		/*
		 * we cannot refer relation cache on the very early phase
		 * in bootstraping mode. we assumes tables has a default
		 * security context as is, and nobody relabel it.
		 */
		relsid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
									 SECCLASS_DB_TABLE);
	}
	else
	{
		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(attForm->attrelid),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "SELinux: cache lookup failed for relation: %u",
				 attForm->attrelid);

		relsid = HeapTupleGetSecLabel(reltup);

		ReleaseSysCache(reltup);
	}

	return sepgsqlClientCreate(relsid, SECCLASS_DB_COLUMN);
}

static sepgsql_sid_t
defaultBlobSecLabel(Relation rel, HeapTuple tuple)
{
	sepgsql_sid_t	losid;
	char			audit_name[64];
	Form_pg_largeobject	loForm
		= (Form_pg_largeobject) GETSTRUCT(tuple);
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
	losid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
								SECCLASS_DB_BLOB);

	snprintf(audit_name, sizeof(audit_name), "blob:%u", loForm->loid);
	sepgsqlClientHasPerms(losid,
						  SECCLASS_DB_BLOB,
						  DB_BLOB__CREATE,
						  audit_name, true);
	return losid;
}

static sepgsql_sid_t
defaultTupleSecLabel(Relation rel, HeapTuple tuple)
{
	HeapTuple           reltup;
	sepgsql_sid_t       relsid;

	if (IsBootstrapProcessingMode() &&
		(RelationGetRelid(rel) == TypeRelationId ||
		 RelationGetRelid(rel) == ProcedureRelationId ||
		 RelationGetRelid(rel) == AttributeRelationId ||
		 RelationGetRelid(rel) == RelationRelationId))
	{
		/*
		 * we cannot refer relation cache on the very early phase
		 * in bootstraping mode. we assumes tables has a default
		 * security context as is, and nobody relabel it.
		 */
		relsid = sepgsqlClientCreate(sepgsqlGetDatabaseSid(),
									 SECCLASS_DB_TABLE);
	}
	else
    {
		reltup = SearchSysCache(RELOID,
								ObjectIdGetDatum(RelationGetRelid(rel)),
								0, 0, 0);
		if (!HeapTupleIsValid(reltup))
			elog(ERROR, "SELinux: cache lookup failed for relation: %u",
				 RelationGetRelid(rel));

		relsid = HeapTupleGetSecLabel(reltup);

		ReleaseSysCache(reltup);
	}

	return sepgsqlClientCreate(relsid, SECCLASS_DB_TUPLE);
}

void
sepgsqlSetDefaultSecLabel(Relation rel, HeapTuple tuple)
{
	security_class_t	tclass;
	sepgsql_sid_t		newsid;

	Assert(HeapTupleHasSecLabel(tuple));
	tclass = sepgsqlTupleObjectClass(RelationGetRelid(rel), tuple);

	switch (tclass)
	{
	case SECCLASS_DB_DATABASE:
		newsid = defaultDatabaseSecLabel(rel, tuple);
		break;

	case SECCLASS_DB_TABLE:
		newsid = defaultTableSecLabel(rel, tuple);
		break;

	case SECCLASS_DB_PROCEDURE:
		newsid = defaultProcedureSecLabel(rel, tuple);
		break;

	case SECCLASS_DB_COLUMN:
		newsid = defaultColumnSecLabel(rel, tuple);
		break;

	case SECCLASS_DB_BLOB:
		newsid = defaultBlobSecLabel(rel, tuple);
		break;

	default:	/* SECCLASS_DB_TUPLE */
		newsid = defaultTupleSecLabel(rel, tuple);
		break;
	}

	HeapTupleSetSecLabel(tuple, newsid);
}
