/*
 * src/backend/utils/sepgsql/perms.c
 *   SE-PostgreSQL permission managements
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_namespace.h"
#include "miscadmin.h"
#include "security/sepgsql.h"

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
			{ "connect",		SEPG_DB_DATABASE__CONNECT },
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
			{ "add_object",		SEPG_DB_SCHEMA__ADD_OBJECT },
			{ "remove_object",	SEPG_DB_SCHEMA__REMOVE_OBJECT },
			{ NULL, 0UL },
		}
	},
	{
		"db_schema_temp",		SEPG_CLASS_DB_SCHEMA_TEMP,
		{
			{ "create",			SEPG_DB_SCHEMA_TEMP__CREATE },
			{ "drop",			SEPG_DB_SCHEMA_TEMP__DROP},
			{ "getattr",		SEPG_DB_SCHEMA_TEMP__GETATTR },
			{ "setattr",		SEPG_DB_SCHEMA_TEMP__SETATTR },
			{ "relabelfrom",	SEPG_DB_SCHEMA_TEMP__RELABELFROM },
			{ "relabelto",		SEPG_DB_SCHEMA_TEMP__RELABELTO },
			{ "search",			SEPG_DB_SCHEMA_TEMP__SEARCH },
			{ "add_object",		SEPG_DB_SCHEMA_TEMP__ADD_OBJECT },
			{ "remove_object",	SEPG_DB_SCHEMA_TEMP__REMOVE_OBJECT },
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
 * sepgsqlAuditName
 *
 * It returns an identifier string to generate audit record
 * for the given tuple.
 */
const char *
sepgsqlAuditName(Oid relid, HeapTuple tuple)
{
	switch (relid)
	{
	case DatabaseRelationId:
		return NameStr(((Form_pg_database) GETSTRUCT(tuple))->datname);

	case NamespaceRelationId:
		return NameStr(((Form_pg_namespace) GETSTRUCT(tuple))->nspname);

	case ProcedureRelationId:
		return NameStr(((Form_pg_proc) GETSTRUCT(tuple))->proname);
	}
	return NULL;
}

/*
 * sepgsqlTransToExternalClass
 *
 * It translates an internal object class code (defined as SEPGCLASS_*)
 * into external code which is necessary to communicate in-kernel SELinux.
 */
security_class_t
sepgsqlTransToExternalClass(uint16 tclass_in)
{
	const char *tclass_name;

	Assert(tclass_in < SEPG_CLASS_MAX);

	tclass_name = selinux_catalog[tclass_in].class_name;

	return string_to_security_class(tclass_name);
}

void
sepgsqlTransToInternalPerms(security_class_t tclass_in,
                            struct av_decision *avd_ex)
{
	struct av_decision	avd_in;
	security_class_t	tclass_ex;
	int		i, deny_unknown;

	Assert(tclass_in < SEPG_CLASS_MAX);

	memset(&avd_in, 0, sizeof(avd_in));

	deny_unknown = security_deny_unknown();

	tclass_ex = sepgsqlTransToExternalClass(tclass_in);

	for (i=0; selinux_catalog[tclass_in].av[i].perm_name; i++)
	{
		const char	   *perm_name = selinux_catalog[tclass_in].av[i].perm_name;
		access_vector_t	perm_code_in = selinux_catalog[tclass_in].av[i].perm_code;
		access_vector_t perm_code_ex;

		perm_code_ex = string_to_av_perm(tclass_ex, perm_name);
		if (!perm_code_ex)
		{
			/* fill up undefined permission */
			if (!deny_unknown)
				avd_in.allowed |= perm_code_in;
			avd_in.decided |= perm_code_in;
			avd_in.auditdeny |= perm_code_in;
			continue;
		}

		if (avd_ex->allowed & perm_code_ex)
			avd_in.allowed |= perm_code_in;
		if (avd_ex->decided & perm_code_ex)
			avd_in.decided |= perm_code_in;
		if (avd_ex->auditallow & perm_code_ex)
			avd_in.auditallow |= perm_code_in;
		if (avd_ex->auditdeny & perm_code_ex)
			avd_in.auditdeny |= perm_code_in;
	}
	memcpy(avd_ex, &avd_in, sizeof(avd_in));
}

/*
 * sepgsqlGetClassString
 *
 * It returns text representation of object class.
 */
const char *
sepgsqlGetClassString(uint16 tclass)
{
	Assert(tclass < SEPG_CLASS_MAX);

	return selinux_catalog[tclass].class_name;
}

/*
 * sepgsqlGetPermString
 *
 * It returns text representation of object class.
 */
const char *
sepgsqlGetPermString(uint16 tclass, uint32 perm_code)
{
	int		i;

	Assert(tclass < SEPG_CLASS_MAX);

	for (i=0; selinux_catalog[tclass].av[i].perm_name; i++)
	{
		if (selinux_catalog[tclass].av[i].perm_code == perm_code)
			return selinux_catalog[tclass].av[i].perm_name;
	}
	return NULL;
}
