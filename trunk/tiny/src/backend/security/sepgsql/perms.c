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
		"db_database",			SEPG_CLASS_DB_DATABASE,
		{
			{ "connect",		SEPG_DB_DATABASE__CONNECT },
			{ "superuser",		SEPG_DB_DATABASE__SUPERUSER },
			{ NULL, 0UL },
		}
	},
	{
		"db_schema",			SEPG_CLASS_DB_SCHEMA,
		{
			{ "usage",			SEPG_DB_SCHEMA__USAGE },
			{ NULL, 0UL },
		}
	},
	{
		"db_schema_temp",		SEPG_CLASS_DB_SCHEMA_TEMP,
		{
			{ "usage",			SEPG_DB_SCHEMA_TEMP__USAGE },
			{ NULL, 0UL },
		}
	},
	{
		"db_procedure",			SEPG_CLASS_DB_PROCEDURE,
		{
			{ "execute",		SEPG_DB_PROCEDURE__EXECUTE },
			{ NULL, 0UL },
		}
	},
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
