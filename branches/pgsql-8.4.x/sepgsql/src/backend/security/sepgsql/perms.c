/*
 * src/backend/utils/sepgsql/perms.c
 *   SE-PostgreSQL permission checks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/lsyscache.h"

/*
 * Dynamic object class/permissions mapping
 *
 * SELinux exports the list of object classes and permissions at
 * /selinux/class. The libselinux provides an interface to translate
 * between their names and codes.
 */
static struct
{
	const char		   *class_name;
	security_class_t	class_code;
	struct
	{
		const char	   *perm_name;
		access_vector_t	perm_code;
	} av[sizeof(access_vector_t) * 8];
} selinux_catalog[] = {
	{
		"process",				SEPG_CLASS_PROCESS,
		{
			{"translation",		SEPG_PROCESS__TRANSITION },
			{NULL, 0}
		}
	},
	{
		"file",					SEPG_CLASS_FILE,
		{
			{"read",			SEPG_FILE__READ },
			{"write",			SEPG_FILE__WRITE },
			{NULL, 0}
		}
	},
	{
		"dir",					SEPG_CLASS_DIR,
		{
			{"read",			SEPG_DIR__READ },
			{"write",			SEPG_DIR__WRITE },
			{NULL,0}
		}
	},
	{
		"lnk_file",				SEPG_CLASS_LNK_FILE,
		{
			{"read",			SEPG_LNK_FILE__READ },
			{"write",			SEPG_LNK_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"chr_file",				SEPG_CLASS_CHR_FILE,
		{
			{"read",			SEPG_CHR_FILE__READ },
			{"write",			SEPG_CHR_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"blk_file",				SEPG_CLASS_BLK_FILE,
		{
			{"read",			SEPG_BLK_FILE__READ },
			{"write",			SEPG_BLK_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"sock_file",			SEPG_CLASS_SOCK_FILE,
		{
			{"read",			SEPG_SOCK_FILE__READ },
			{"write",			SEPG_SOCK_FILE__WRITE },
			{NULL,0}
		}
	},
	{
		"fifo_file",			SEPG_CLASS_FIFO_FILE,
		{
			{"read",			SEPG_FIFO_FILE__READ },
			{"write",			SEPG_FIFO_FILE__WRITE },
			{NULL, 0UL }
		}
	},
	{
		"db_database",			SEPG_CLASS_DB_DATABASE,
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
			{ "superuser",		SEPG_DB_DATABASE__SUPERUSER },
			{ NULL, 0UL },
		}
	},
	{
		"db_schema",			SEPG_CLASS_DB_SCHEMA,
		{
			{ "create",			SEPG_DB_SCHEMA__CREATE },
			{ "drop",			SEPG_DB_SCHEMA__DROP },
			{ "getattr",		SEPG_DB_SCHEMA__GETATTR },
			{ "setattr",		SEPG_DB_SCHEMA__SETATTR },
			{ "relabelfrom",	SEPG_DB_SCHEMA__RELABELFROM },
			{ "relabelto",		SEPG_DB_SCHEMA__RELABELTO },
			{ "search",			SEPG_DB_SCHEMA__SEARCH },
			{ "add_name",		SEPG_DB_SCHEMA__ADD_NAME },
			{ "remove_name",	SEPG_DB_SCHEMA__REMOVE_NAME },
			{ NULL, 0UL },
		}
	},
	{
		"db_table",				SEPG_CLASS_DB_TABLE,
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
			{ "reference",		SEPG_DB_TABLE__REFERENCE },
			{ NULL, 0UL },
		}
	},
	{
		"db_sequence",			SEPG_CLASS_DB_SEQUENCE,
		{
			{ "create",			SEPG_DB_SEQUENCE__CREATE },
			{ "drop",			SEPG_DB_SEQUENCE__DROP },
			{ "getattr",		SEPG_DB_SEQUENCE__GETATTR },
			{ "setattr",		SEPG_DB_SEQUENCE__SETATTR },
			{ "relabelfrom",	SEPG_DB_SEQUENCE__RELABELFROM },
			{ "relabelto",		SEPG_DB_SEQUENCE__RELABELTO },
			{ "get_value",		SEPG_DB_SEQUENCE__GET_VALUE },
			{ "next_value",		SEPG_DB_SEQUENCE__NEXT_VALUE },
			{ "set_value",		SEPG_DB_SEQUENCE__SET_VALUE },
			{ NULL, 0UL },
		}
	},
	{
		"db_procedure",			SEPG_CLASS_DB_PROCEDURE,
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
			{ "untrusted",		SEPG_DB_PROCEDURE__UNTRUSTED },
			{ NULL, 0UL },
		}
	},
	{
		"db_column",			SEPG_CLASS_DB_COLUMN,
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
			{ "reference",		SEPG_DB_COLUMN__REFERENCE },
			{ NULL, 0UL },
		}
	},
	{
		"db_tuple",				SEPG_CLASS_DB_TUPLE,
		{
			{ "relabelfrom",	SEPG_DB_TUPLE__RELABELFROM },
			{ "relabelto",		SEPG_DB_TUPLE__RELABELTO },
			{ "select",			SEPG_DB_TUPLE__SELECT },
			{ "update",			SEPG_DB_TUPLE__UPDATE },
			{ "insert",			SEPG_DB_TUPLE__INSERT },
			{ "delete",			SEPG_DB_TUPLE__DELETE },
			{ NULL, 0UL },
		}
	},
	{
		"db_blob",				SEPG_CLASS_DB_BLOB,
		{
			{ "create",			SEPG_DB_BLOB__CREATE },
			{ "drop",			SEPG_DB_BLOB__DROP },
			{ "getattr",		SEPG_DB_BLOB__GETATTR },
			{ "setattr",		SEPG_DB_BLOB__SETATTR },
			{ "relabelfrom",	SEPG_DB_BLOB__RELABELFROM },
			{ "relabelto",		SEPG_DB_BLOB__RELABELTO },
			{ "read",			SEPG_DB_BLOB__READ },
			{ "write",			SEPG_DB_BLOB__WRITE },
			{ "import",			SEPG_DB_BLOB__IMPORT },
			{ "export",			SEPG_DB_BLOB__EXPORT },
			{ NULL, 0UL },
		}
	}
};

/*
 * sepgsqlTransToExternalClass
 *   It translate the given class code (defined as SEPGCLASS_(class)) into
 *   external code which is necessary to communicate in-kernel SELinux
 */
extern security_class_t
sepgsqlTransToExternalClass(uint16 tclass)
{
	Assert(tclass < SEPG_CLASS_MAX);

	return string_to_security_class(selinux_catalog[tclass].class_name);
}

/*
 * sepgsqlTransToInternalPerms
 *   It translate the given permission masks into internal representation
 *   defined as SEPG_(class)_(permission).
 */
extern void
sepgsqlTransToInternalPerms(security_class_t tclass, struct av_decision *avd)
{
	security_class_t tclass_ex;
	struct av_decision i_avd;
	int i, deny_unknown;

	Assert(tclass < SEPG_CLASS_MAX);

	memset(&i_avd, 0, sizeof(struct av_decision));

	deny_unknown = security_deny_unknown();

	tclass_ex = sepgsqlTransToExternalClass(tclass);
	for (i=0; selinux_catalog[tclass].av[i].perm_name; i++)
	{
		const char	   *perm_name = selinux_catalog[tclass].av[i].perm_name;
		access_vector_t	perm_code = selinux_catalog[tclass].av[i].perm_code;
		access_vector_t	perm_code_ex;

		perm_code_ex = string_to_av_perm(tclass_ex, perm_name);
		if (!perm_code_ex)
		{
			/* fill up undefined permission */
			if (!deny_unknown)
				i_avd.allowed |= perm_code;
			i_avd.decided |= perm_code;
			i_avd.auditdeny |= perm_code;
			continue;
		}

		if (avd->allowed & perm_code_ex)
			i_avd.allowed |= perm_code;
		if (avd->decided & perm_code_ex)
			i_avd.decided |= perm_code;
		if (avd->auditallow & perm_code_ex)
			i_avd.auditallow |= perm_code;
		if (avd->auditdeny & perm_code_ex)
			i_avd.auditdeny |= perm_code;
	}

	avd->allowed = i_avd.allowed;
	avd->decided = i_avd.decided;
	avd->auditallow = i_avd.auditallow;
	avd->auditdeny = i_avd.auditdeny;
}

/*
 * sepgsqlGetClassString
 * sepgsqlGetPermissionString
 *   It returns text representation of object classes/permissions
 */
const char *
sepgsqlGetClassString(uint16 tclass)
{
	Assert(tclass < SEPG_CLASS_MAX);

	return selinux_catalog[tclass].class_name;
}

const char *
sepgsqlGetPermString(uint16 tclass, uint32 permission)
{
	int		i;

	Assert(tclass < SEPG_CLASS_MAX);

	for (i=0; selinux_catalog[tclass].av[i].perm_name; i++)
	{
		if (selinux_catalog[tclass].av[i].perm_code == permission)
			return selinux_catalog[tclass].av[i].perm_name;
	}
	return NULL;
}

/*
 * sepgsqlFileObjectClass
 *
 * It returns proper object class of filesystem object already opened.
 * It is necessary to check privileges voluntarily.
 */
uint16
sepgsqlFileObjectClass(int fdesc)
{
	struct stat stbuf;

	if (fstat(fdesc, &stbuf) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not stat file descriptor: %d", fdesc)));

	if (S_ISDIR(stbuf.st_mode))
		return SEPG_CLASS_DIR;
	else if (S_ISCHR(stbuf.st_mode))
		return SEPG_CLASS_CHR_FILE;
	else if (S_ISBLK(stbuf.st_mode))
		return SEPG_CLASS_BLK_FILE;
	else if (S_ISFIFO(stbuf.st_mode))
		return SEPG_CLASS_FIFO_FILE;
	else if (S_ISLNK(stbuf.st_mode))
		return SEPG_CLASS_LNK_FILE;
	else if (S_ISSOCK(stbuf.st_mode))
		return SEPG_CLASS_SOCK_FILE;

	return SEPG_CLASS_FILE;
}

/*
 * sepgsqlTupleObjectClass
 *
 * It returns correct object class of given tuple
 */
uint16
sepgsqlTupleObjectClass(Oid relid, HeapTuple tuple)
{
	Form_pg_class clsForm;
	Form_pg_attribute attForm;

	switch (relid)
	{
	case DatabaseRelationId:
		return SEPG_CLASS_DB_DATABASE;

	case NamespaceRelationId:
		return SEPG_CLASS_DB_SCHEMA;

	case RelationRelationId:
		clsForm = (Form_pg_class) GETSTRUCT(tuple);
		if (clsForm->relkind == RELKIND_RELATION)
			return SEPG_CLASS_DB_TABLE;
		if (clsForm->relkind == RELKIND_SEQUENCE)
			return SEPG_CLASS_DB_SEQUENCE;
		break;

	case AttributeRelationId:
		attForm = (Form_pg_attribute) GETSTRUCT(tuple);
		if (IsBootstrapProcessingMode() &&
			(attForm->attrelid == TypeRelationId      ||
			 attForm->attrelid == ProcedureRelationId ||
			 attForm->attrelid == AttributeRelationId ||
			 attForm->attrelid == RelationRelationId))
			return SEPG_CLASS_DB_COLUMN;

		if (get_rel_relkind(attForm->attrelid) == RELKIND_RELATION)
			return SEPG_CLASS_DB_COLUMN;
		break;

	case ProcedureRelationId:
		return SEPG_CLASS_DB_PROCEDURE;

	case LargeObjectRelationId:
		return SEPG_CLASS_DB_BLOB;
	}
	return SEPG_CLASS_DB_TUPLE;
}
