/*
 * src/backend/security/sepgsql/selinux.c
 *   Routines to communicate with SELinux.
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "security/sepgsql.h"







/*
 * selinux_catalog
 *
 * It is a static table to associate internal codes with its name of object
 * classes and permissions.
 * SELinux requires applications to use 
 *
 *
 *
 *
 *
 *
 */
static struct
{
	const char	   *class_name;
	uint16			class_code;
	struct
	{
		const char *perm_name;
		uint32		perm_code;
	} perms[32];
} selinux_catalog[] = {
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
		"db_table",             SEPG_CLASS_DB_TABLE,
		{
			{ "create",         SEPG_DB_TABLE__CREATE },
			{ "drop",           SEPG_DB_TABLE__DROP },
			{ "getattr",        SEPG_DB_TABLE__GETATTR },
			{ "setattr",        SEPG_DB_TABLE__SETATTR },
			{ "relabelfrom",    SEPG_DB_TABLE__RELABELFROM },
			{ "relabelto",      SEPG_DB_TABLE__RELABELTO },
			{ "select",         SEPG_DB_TABLE__SELECT },
			{ "update",         SEPG_DB_TABLE__UPDATE },
			{ "insert",         SEPG_DB_TABLE__INSERT },
			{ "delete",         SEPG_DB_TABLE__DELETE },
			{ "lock",           SEPG_DB_TABLE__LOCK },
			{ "reference",      SEPG_DB_TABLE__REFERENCE },
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
};

/*
 * sepgsql_is_enabled
 *
 *
 */
bool
sepgsql_is_enabled(void)
{
	static int	enabled = -1;

	/*
	 * If sepostgresql = disabled, it always returns FALSE
	 * independently from the system status.
	 */
	if (sepostgresql_mode == SEPGSQL_MODE_DISABLED)
		return false;

	if (enabled < 0)
		enabled = is_selinux_enabled();

	return enabled > 0 ? true : false;
}

/*
 * sepgsql_get_enforce
 *
 *
 *
 */
bool
sepgsql_get_enforce(void)
{
	if (sepostgresql_mode == SEPGSQL_MODE_DEFAULT)
	{
		if (security_getenforce() == 1)
			return true;
	}
	else if (sepostgresql_mode == SEPGSQL_MODE_ENFORCING)
		return true;

	return false;
}

/*
 * sepgsql_audit_log
 *
 *
 *
 *
 */
PGDLLIMPORT sepgsql_audit_hook_t sepgsql_audit_hook = NULL;

static void
sepgsql_audit_log(bool denied, char *scontext, char *tcontext,
				  uint16 tclass, uint32 audited, const char *audit_name)
{
	StringInfoData	buf;
	uint32			mask;
	const char	   *tclass_name;
	const char	   *perm_name;

	/*
	 * translation of security contexts to human readable format
	 */
	if (sepostgresql_mcstrans)
	{
		scontext = sepgsql_mcstrans_out(scontext);
		tcontext = sepgsql_mcstrans_out(tcontext);
	}

	/* lookup name of the object class */
	tclass_name = selinux_catalog[tclass].class_name;

	/* lookup name of the permissions */
	initStringInfo(&buf);
	appendStringInfo(&buf, "{");
	for (mask = 1; audited != 0; mask <<= 1)
	{
		if (audited & mask)
		{
			perm_name = selinux_catalog[tclass].av[mask].perm_name;
			appendStringInfo(&buf, " %s", perm_name);
		}

		audited &= ~mask;
	}
	appendStringInfo(&buf, " }");

	/*
	 * Call external audit module, if loaded
	 */
	if (sepgsql_audit_hook)
		(*sepgsql_audit_hook)(denied, scontext, tcontext,
							  tclass_name, buf.data, audit_name);
	else
	{
		appendStringInfo(&buf, " scontext=%s tcontext=%s tclass=%s",
						 scontext, tcontext, tclass_name);
		if (audit_name)
			appendStringInfo(&buf, " name=%s", audit_name);

		ereport(LOG,
				(errmsg("SELinux: %s %s",
						denied ? "denied" ? "allowed", buf.data)));
	}
}

/*
 * compute_perms_internal
 *
 *
 *
 *
 *
 */
static void
compute_perms_internal(char *scontext, char *tcontext,
					   uint16 tclass, struct av_decision *avd)
{
	const char		   *tclass_name;
	security_class_t	tclass_ex;
	struct av_decision	avd_ex;
	int					i, deny_unknown = security_deny_unknown();

	/* Get external code of the object class*/
	Assert(tclass < SEPG_CLASS_MAX);

	tclass_name = selinux_catalog[tclass].class_name;
	tclass_ex = string_to_security_class(tclass_name);

	if (tclass_ex == 0)
	{
		/*
		 * If the current security policy does not support permissions
		 * corresponding to database objects, we fill up them with dummy
		 * data.
		 * If security_deny_unknown() returns positive value, undefined
		 * permissions should be denied. Otherwise, allowed
		 */
		avd->allowed = (deny_unknown > 0 ? 0 : ~0UL);
		avd->auditallow = 0UL;
		avd->auditdeny = ~0UL;
		avd->flags = 0;

		return;
	}

	/*
	 * Ask SELinux what is allowed set of permissions on a pair of the
	 * security contexts and the given object class.
	 */
	if (security_compute_av_flags_raw(scontext, tcontext,
									  tclass_ex, 0, &avd_ex) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux could not compute av_decision: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, tclass_name)));

	memset(avd, 0, sizeof(struct av_decision));

	for (i=0; selinux_catalog[tclass].av[i].perm_name; i++)
	{
		access_vector_t		perm_code_ex;
		const char *perm_name = selinux_catalog[tclass].av[i].perm_name;
		uint32		perm_code = selinux_catalog[tclass].av[i].perm_code;

		perm_code_ex = string_to_av_perm(tclass_ex, perm_name);
		if (perm_code_ex == 0)
		{
			/* fill up undefined permissions */
			if (!deny_unknown)
				avd->allowed |= perm_code;
			avd->auditdeny |= perm_code;

			continue;
		}

		if (avd_ex.allowed & perm_code_ex)
			avd->allowed |= perm_code;
		if (avd_ex.auditallow & perm_code_ex)
			avd->auditallow |= perm_code;
		if (avd_ex.auditdeny & perm_code_ex)
			avd->auditdeny |= perm_code;
	}

	return;
}

/*
 * compute_create_internal
 *
 *
 *
 *
 */
static char *
compute_create_internal(char *scontext, char *tcontext, uint16 tclass)
{
	security_context_t	ncontext;
	security_class_t	tclass_ex;
	const char		   *tclass_name;

	/* Get external code of the object class*/
	Assert(tclass < SEPG_CLASS_MAX);

	tclass_name = selinux_catalog[tclass].class_name;
	tclass_ex = string_to_security_class(tclass_name);

	/*
	 * Ask SELinux what is the default context for the given object class
	 * on a pair of security contexts
	 */
	if (security_compute_create_raw(scontext, tcontext,
									tclass_ex, &ncontext))
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("SELinux could not compute a new context: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, tclass_name)));
	/*
	 * libselinux returns malloc()'ed string, so we need to copy it
	 * on the palloc()'ed region.
	 */
	PG_TRY();
	{
		result = pstrdup(ncontext);
	}
	PG_CATCH();
	{
		freecon(ncontext);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(ncontext);

	return result;
}

/*
 * sepgsql_compute_perms
 *
 *
 *
 *
 *
 */
extern bool
sepgsql_compute_perms(char *scontext, char *tcontext,
                      uint16 tclass, uint32 required,
                      const char *audit_name, bool abort)
{
	struct av_decision	avd;
	uint32		denied;
	uint32		audited;

	compute_perms_internal(scontext, tcontext, tclass, &avd);

	/*
	 * It logs a security audit record for the given request, if necessary.
	 * When SE-PgSQL performs 'internal' mode, it needs to keep silent.
	 */
	denied = required & ~avd.allowed;
	audited = denied ? (denied & avd.auditdeny)
					 : (required & avd.auditallow);
	if (audited &&
		sepostgresql_mode != SEPGSQL_MODE_INTERNAL)
	{
		sepgsql_audit_log(!!denied, scontext, tcontext,
						  tclass, audited, audit_name);
	}

	if (!denied ||						/* no policy violation */
		!sepgsql_get_enforce() ||		/* permissive mode */
		(avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE) != 0)	/* permissive domain*/
		return true;

	if (abort)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("SELinux: security policy violation")));

	return false;
}

/*
 * sepgsql_compute_create
 *
 *
 *
 *
 *
 */
char *
sepgsql_compute_create(char *scontext, char *tcontext, uint16 tclass)
{
	/*
	 * sanity check for the given security contexts
	 */
	if (security_check_context_raw(scontext) < 0)
		scontext = sepgsql_get_unlabeled_context();

	if (security_check_context_raw(tcontext) < 0)
		tcontext = sepgsql_get_unlabeled_context();

	return compute_create_internal(scontext, tcontext, tclass);
}
