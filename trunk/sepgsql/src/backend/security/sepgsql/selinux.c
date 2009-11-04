/*
 * src/backend/security/sepgsql/selinux.c
 *   Routines to communicate with SELinux.
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "lib/stringinfo.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "security/sepgsql.h"

#include <selinux/selinux.h>

/*
 * selinux_catalog
 *
 * This static translation lookup table enables to associate a certain
 * object class/permission name with its internal code, such as
 * SEPG_CLASS_DB_SCHEMA.
 *
 * SELinux requires applications to represent object class and a set of
 * permissions in code, instead of its name, when we ask SELinux's decision.
 *
 * See the definition of security_compute_av(3) API in libselinux.
 * We need to gives a code of object class, and interpret what permissions
 * are allowed on the object class from av_decision structure.
 * Actual values of the code depend on the security policy. In other words,
 * we cannot know what number is assigned on a certain object class and
 * permissions.
 * The string_to_security_class(3) and string_to_av_perm(3) APIs takes
 * arguments with the name of object class/permission, and returns the
 * code for the given object class/permissions.
 * For example, we can know what code is assigned on the "db_table" class
 * using these functions as follows:
 *
 *   uint16 tclass_ex = string_to_security_class("db_table");
 *
 * On the other hand, we use an alternative code internally to simplify
 * the implementation, such as SEPG_CLASS_* for object class.
 * The following selinux_catalog is used to translate the 'internal'
 * code and the 'external' code.
 *
 * It allows to lookup name of the object class or permission corresponding
 * to a certain 'internal' code. Then, we can give the name to SELinux's
 * API to obtain 'external' code which can be used to ask in-kernel SELinux.
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
 * GUC option: sepostgresql = [default|enforcing|permissive|disabled]
 *
 * SEPGSQL_MODE_DEFAULT		: It follows system setting
 * SEPGSQL_MODE_ENFORCING	: Use enforcing mode always
 * SEPGSQL_MODE_PERMISSIVE	: Use permissive mode always
 * SEPGSQL_MODE_INTERNAL	: Internally used mode. Same as permissive mode
 *							  except for silence in audit logs
 * SEPGSQL_MODE_DISABLED	: It always disables SE-PgSQL configuration
 */
int sepostgresql_mode;

/*
 * sepgsql_initialize
 *
 * It sets up the privilege (security context) of the client and initializes
 * a few internal stuff.
 */
void
sepgsql_initialize(void)
{
	char   *context;

	if (!sepgsql_is_enabled())
		return;

	if (!MyProcPort)
	{
		/*
		 * SE-PgSQL does not prevent anything in single-user mode.
		 */
		sepostgresql_mode = SEPGSQL_MODE_INTERNAL;

		/*
		 * When this server process was launched in single-user mode,
		 * it does not have any client socket, and the server process also
		 * performs as a client in same time. So, we apply a security context
		 * of the current process as a client's one.
		 * The getcon_raw(3) is an libselinux API to obtain security context
		 * of the current process in raw format.
		 */
		if (getcon_raw(&context) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_INTERNAL_ERROR),
					 errmsg("SELinux: could not get server context")));
	}
	else
	{
		/*
		 * Otherwise, SE-PgSQL obtains the security context of the client
		 * process using getpeercon(3). It is an API of SELinux to obtain
		 * the security context of the peer process for the given file
		 * descriptor of the client socket.
		 * For example, a process labeled as "system_u:system_r:httpd_t:s0"
		 * (which is typically apache/httpd) connect to the PgSQL server,
		 * getpeercon_raw() in server side returns the security context
		 * in client side.
		 * If MyProcPort->sock came from unix domain socket, we don't need
		 * any special configuration. OS handles them correctly.
		 * If it is tcp/ip socket, either labeled ipsec or static fallback
		 * context should be configured.
		 * The labeled ipsec is a feature to deliver the security context
		 * of remote peer processes with an enhancement of key exchange
		 * server (racoon). If SELinux is also available in the client host
		 * also, it is the most preferable option.
		 * The static fallback context is a feature to assign an alternative
		 * security context based on the source address and network device
		 * in usage. It can be applied, even if Windows is run on the client.
		 */
		if (getpeercon_raw(MyProcPort->sock, &context) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_INTERNAL_ERROR),
					 errmsg("SELinux: could not get client context")));
	}
	sepgsql_set_client_context(context);
}

/*
 * sepgsql_is_enabled
 *
 * If it returns true, SE-PgSQL is enabled. Otherwise, it is disabled.
 */
bool
sepgsql_is_enabled(void)
{
	static int	enabled = -1;

	/*
	 * Not ready to apply SE-PgSQL feature in bootstraping mode
	 */
	if (IsBootstrapProcessingMode())
		return false;

	/*
	 * If sepostgresql = disabled, it always returns FALSE
	 * independently from the system status.
	 */
	if (sepostgresql_mode == SEPGSQL_MODE_DISABLED)
		return false;

	/*
	 * SE-PgSQL needs SELinux is enabled on the operating system.
	 * If it is disabled, SE-PgSQL has to be also disabled, even if
	 * 'enforcing' or 'permissive' are specified.
	 */
	if (enabled < 0)
		enabled = is_selinux_enabled();

	return enabled > 0 ? true : false;
}

/*
 * sepgsql_get_enforce
 *
 * It returns true, if SE-PgSQL performs in enforcing mode.
 *
 * In enforcing mode, SE-PgSQL performs as expected. It checks permissions
 * on the required action, and it prevents them if violated.
 * In permissive mode, SE-PgSQL also checks permissions, but it does not
 * prevent anything, even if violated. It generates audit logs for access
 * violations, so we can use this mode to debug security policy itself.
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
	const char	   *tclass_name;
	const char	   *perm_name;
	int				i;

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

	for (i=0; selinux_catalog[tclass].perms[i].perm_name; i++)
	{
		if (audited & (1UL << i))
		{
			perm_name = selinux_catalog[tclass].perms[i].perm_name;
			appendStringInfo(&buf, " %s", perm_name);
		}
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
				(errcode(ERRCODE_SELINUX_AUDIT_LOG),
				 errmsg("SELinux: %s %s",
						(denied ? "denied" : "allowed"), buf.data)));
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
				(errcode(ERRCODE_SELINUX_INTERNAL_ERROR),
				 errmsg("SELinux could not compute av_decision: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, tclass_name)));

	memset(avd, 0, sizeof(struct av_decision));

	for (i=0; selinux_catalog[tclass].perms[i].perm_name; i++)
	{
		access_vector_t		perm_code_ex;
		const char *perm_name = selinux_catalog[tclass].perms[i].perm_name;
		uint32		perm_code = selinux_catalog[tclass].perms[i].perm_code;

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
	char			   *result;

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
				(errcode(ERRCODE_SELINUX_INTERNAL_ERROR),
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
 * sepgsql_compute_create_name
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

char *
sepgsql_compute_create_name(char *scontext, char *tcontext, char *tclass_name)
{
	int		index;

	for (index = 0; index < SEPG_CLASS_MAX; index++)
	{
		if (strcmp(tclass_name, selinux_catalog[index].class_name) == 0)
		{
			return sepgsql_compute_create(scontext, tcontext,
										  selinux_catalog[index].class_code);
		}
	}
	ereport(ERROR,
			(errcode(ERRCODE_SELINUX_INTERNAL_ERROR),
			 errmsg("unknown object class \"%s\"", tclass_name)));
}
