/*
 * src/backend/utils/sepgsql/perms.c
 *   SE-PostgreSQL permission checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

static struct
{
	const char		   *class_name;
	security_class_t	class_code;
	struct
	{
		const char	   *perm_name;
		access_vector_t	perm_code;
	} av[sizeof(access_vector_t) * 8];
} selinux_permissions[] = {
	{
		"process",				SEPGCLASS_PROCESS,
		{
			{"translation",		SEPG_PROCESS__TRANSITION },
			{NULL, 0}
		}
	},
	{
		"file",					SEPGCLASS_FILE,
		{
			{"read",			SEPG_FILE__READ },
			{"write",			SEPG_FILE__WRITE },
			{NULL, 0}
		}
	},
	{
		"dir",					SEPGCLASS_DIR,
		{
			{"read",			SEPG_DIR__READ },
			{"write",			SEPG_DIR__WRITE },
			{NULL,0}
		}
	},
	{
		"lnk_file",				SEPGCLASS_LNK_FILE,
		{
			{"read",			SEPG_LNK_FILE__READ },
			{"write",			SEPG_LNK_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"chr_file",				SEPGCLASS_CHR_FILE,
		{
			{"read",			SEPG_CHR_FILE__READ },
			{"write",			SEPG_CHR_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"blk_file",				SEPGCLASS_BLK_FILE,
		{
			{"read",			SEPG_BLK_FILE__READ },
			{"write",			SEPG_BLK_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"sock_file",			SEPGCLASS_SOCK_FILE,
		{
			{"read",			SEPG_SOCK_FILE__READ },
			{"write",			SEPG_SOCK_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"fifo_file",			SEPGCLASS_FIFO_FILE,
		{
			{"read",			SEPG_FIFO_FILE__READ },
			{"write",			SEPG_FIFO_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"db_database",			SEPGCLASS_DB_DATABASE,
		{
			{ "create",			SEPG_DB_DATABASE__CREATE },
			{ "drop",			SEPG_DB_DATABASE__DROP },
			{ "getattr",		SEPG_DB_DATABASE__GETATTR },
			{ "setattr",		SEPG_DB_DATABASE__SETATTR },
			{ "relabelfrom",	SEPG_DB_DATABASE__RELABELFROM },
			{ "relabelto",		SEPG_DB_DATABASE__RELABELTO },
			{ "access",			SEPG_DB_DATABASE__ACCESS },
			{ "install_module",	SEPG_DB_DATABASE__INSTALL_MODULE },
			{ "load_module",	SEPG_DB_DATABASE__LOAD_MODULE },
			{ "get_param",		SEPG_DB_DATABASE__GET_PARAM },
			{ "set_param",		SEPG_DB_DATABASE__SET_PARAM },
			{ NULL, 0UL },
		}
	},
	{
		"db_table",				SEPGCLASS_DB_TABLE,
		{
			{ "create",			SEPG_DB_TABLE__CREATE },
			{ "drop",			SEPG_DB_TABLE__DROP },
			{ "getattr",		SEPG_DB_TABLE__GETATTR },
			{ "setattr",		SEPG_DB_TABLE__SETATTR },
			{ "relabelfrom",	SEPG_DB_TABLE__RELABELFROM },
			{ "relabelto",		SEPG_DB_TABLE__RELABELTO },
			{ "select",			SEPG_DB_TABLE__SELECT },
			{ "update",			SEPG_DB_TABLE__UPDATE },
			{ "insert",			SEPG_DB_TABLE__INSERT },
			{ "delete",			SEPG_DB_TABLE__DELETE },
			{ "lock",			SEPG_DB_TABLE__LOCK },
			{ NULL, 0UL },
		}
	},
	{
		"db_procedure",		SECCLASS_DB_PROCEDURE,
		{
			{ "create",			SEPG_DB_PROCEDURE__CREATE },
			{ "drop",			SEPG_DB_PROCEDURE__DROP },
			{ "getattr",		SEPG_DB_PROCEDURE__GETATTR },
			{ "setattr",		SEPG_DB_PROCEDURE__SETATTR },
			{ "relabelfrom",	SEPG_DB_PROCEDURE__RELABELFROM },
			{ "relabelto",		SEPG_DB_PROCEDURE__RELABELTO },
			{ "execute",		SEPG_DB_PROCEDURE__EXECUTE },
			{ "entrypoint",		SEPG_DB_PROCEDURE__ENTRYPOINT },
			{ "install",		SEPG_DB_PROCEDURE__INSTALL },
			{ NULL, 0UL },
		}
	},
	{
		"db_column",		SECCLASS_DB_COLUMN,
		{
			{ "create",			SEPG_DB_COLUMN__CREATE },
			{ "drop",			SEPG_DB_COLUMN__DROP },
			{ "getattr",		SEPG_DB_COLUMN__GETATTR },
			{ "setattr",		SEPG_DB_COLUMN__SETATTR },
			{ "relabelfrom",	SEPG_DB_COLUMN__RELABELFROM },
			{ "relabelto",		SEPG_DB_COLUMN__RELABELTO },
			{ "select",			SEPG_DB_COLUMN__SELECT },
			{ "update",			SEPG_DB_COLUMN__UPDATE },
			{ "insert",			SEPG_DB_COLUMN__INSERT },
			{ NULL, 0UL },
		}
	},
	{
		"db_tuple",			SECCLASS_DB_TUPLE,
		{
			{ "relabelfrom",	SEPG_DB_TUPLE__RELABELFROM},
			{ "relabelto",		SEPG_DB_TUPLE__RELABELTO},
			{ "select",			SEPG_DB_TUPLE__SELECT},
			{ "update",			SEPG_DB_TUPLE__UPDATE},
			{ "insert",			SEPG_DB_TUPLE__INSERT},
			{ "delete",			SEPG_DB_TUPLE__DELETE},
			{ NULL, 0UL},
		}
	},
	{
		"db_blob",			SECCLASS_DB_BLOB,
		{
			{ "create",			SEPG_DB_BLOB__CREATE},
			{ "drop",			SEPG_DB_BLOB__DROP},
			{ "getattr",		SEPG_DB_BLOB__GETATTR},
			{ "setattr",		SEPG_DB_BLOB__SETATTR},
			{ "relabelfrom",	SEPG_DB_BLOB__RELABELFROM},
			{ "relabelto",		SEPG_DB_BLOB__RELABELTO},
			{ "read",			SEPG_DB_BLOB__READ},
			{ "write",			SEPG_DB_BLOB__WRITE},
			{ "import",			SEPG_DB_BLOB__IMPORT},
			{ "export",			SEPG_DB_BLOB__EXPORT},
			{ NULL, 0UL},
		}
	}
};

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
		rc = sepgsqlClientHasPerms(HeapTupleGetSecLabel(relid, tuple),
								   tclass, av_perms,
								   audit_name, abort);
	}
	return rc;
}
