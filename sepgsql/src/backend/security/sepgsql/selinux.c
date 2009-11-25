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
#include "storage/fd.h"
#include "utils/builtins.h"

#include <fnmatch.h>
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
			{ "inherit",		SEPG_DB_TABLE__INHERIT },
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
int sepgsql_mode;

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
		sepgsql_mode = SEPGSQL_MODE_INTERNAL;

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
					(errcode(ERRCODE_SELINUX_ERROR),
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
					(errcode(ERRCODE_SELINUX_ERROR),
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
	if (sepgsql_mode == SEPGSQL_MODE_DISABLED)
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
	if (sepgsql_mode == SEPGSQL_MODE_DEFAULT)
	{
		if (security_getenforce() == 1)
			return true;
	}
	else if (sepgsql_mode == SEPGSQL_MODE_ENFORCING)
		return true;

	return false;
}

/*
 * sepgsql_show_mode
 *
 * It returns the current performing mode ('selinux_support')
 * in human readable form.
 */
char *
sepgsql_show_mode(void)
{
	if (!sepgsql_is_enabled())
		return "disabled";

	if (!sepgsql_get_enforce())
		return "permissive";

	return "enforcing";
}

/*
 * sepgsql_audit_log
 *
 * It generates a security audit record. In the default, it writes out
 * audit records into standard PG's logfile. It also allows to set up
 * external audit log receiver, such as auditd in Linux, using the
 * sepgsql_audit_hook.
 *
 * SELinux can control what should be audited and should not using
 * "auditdeny" and "auditallow" rules in the security policy. In the
 * default, all the access violations are audited, and all the access
 * allowed are not audited. But we can set up the security policy, so
 * we can have exceptions. So, it is necessary to follow the suggestion
 * come from the security policy. (av_decision.auditallow and auditdeny)
 *
 * Security audit is an important feature, because it enables us to check
 * what was happen if we have a security incident. In fact, ISO/IEC15408
 * defines several security functionalities for audit features.
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
	 * translation of security contexts to human readable format,
	 * if sepgsql_mcstrans is turned on.
	 */
	scontext = sepgsql_mcstrans_out(scontext);
	tcontext = sepgsql_mcstrans_out(tcontext);

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
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("SELinux: %s %s",
						(denied ? "denied" : "allowed"), buf.data)));
	}
}

/*
 * compute_perms_internal
 *
 * It actually asks SELinux what permissions are allowed on a pair of
 * the security contexts and object class. It also returns what permissions
 * should be audited on access violation or allowed.
 * In most cases, subject's security context (scontext) is a client, and
 * target security context (tcontext) is a database object.
 *
 * The access control decision shall be set on the given av_decision.
 * The av_decision.allowed has a bitmask of SEPG_<class>__<perms>
 * to suggest a set of allowed actions in this object class.
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
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux could not compute av_decision: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, tclass_name)));

	/*
	 * SELinux returns its access control decision as a set of permissions
	 * represented in external code which depends on run-time environment.
	 * So, we need to translate it to the internal representation before
	 * returning results for the caller.
	 */
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
 * sepgsql_compute_perms
 *
 * It makes access control decision communicating with SELinux.
 * If SELinux does not allow required permissions on a pair of the security
 * contexts, it raises an error or returns false.
 *
 * scontext : The security context of subject. In most cases, it is client.
 * tcontext : The security context of target database object.
 * tclass   : One of the object class code (SEPG_CLASS_*) declared in the
 *            header file.
 * required : A bitmap of the required permissions (SEPG_<class>__<perm>)
 *            declared in the header file.
 * audit_name : A human readable name of the database object for auditing.
 * abort    : True, if caller want to raise an error on access violation.
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

	if (audited && sepgsql_mode != SEPGSQL_MODE_INTERNAL)
	{
		sepgsql_audit_log(!!denied, scontext, tcontext,
						  tclass, audited, audit_name);
	}

	/*
	 * If here is no policy violations, or SE-PgSQL performs in permissive
	 * mode, or the client process peforms in permissive domain, it returns
	 * normally with 'true'.
	 */
	if (!denied ||
		!sepgsql_get_enforce() ||
		(avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE) != 0)
		return true;

	/*
	 * Otherwise, it raises an error or returns 'false', depending on the
	 * caller's indication by 'abort'.
	 */
	if (abort)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("SELinux: security policy violation")));

	return false;
}

/*
 * sepgsql_compute_create
 *
 * It returns a default security context to be assigned on a new database
 * object. SELinux compute it based on a combination of client, upper object
 * which owns the new object and object class.
 *
 * For example, when a client (staff_u:staff_r:staff_t:s0) tries to create
 * a new table within a schema (system_u:object_r:sepgsql_schema_t:s0),
 * SELinux looks-up its security policy. If it has a special rule on the
 * combination of these security contexts and object class (db_table),
 * it returns the security context suggested by the special rule.
 * Otherwise, it returns the security context of schema, as is.
 *
 * We expect the caller already applies sanity/validation checks on the
 * given security context.
 *
 * scontext : The security context of subject. In most cases, it is client.
 * tcontext : The security context of the parent database object..
 * tclass   : One of the object class code (SEPG_CLASS_*) declared in the
 *            header file.
 */
char *
sepgsql_compute_create(char *scontext, char *tcontext, uint16 tclass)
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
				(errcode(ERRCODE_SELINUX_ERROR),
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
 * sepgsql_template1_getcon
 *
 * It returns a security context to be assigned on the template1 database
 * on the initdb phase.
 *
 * Note that the default security context on a new database is computed
 * based on a pair of the client and the template database. It means we
 * need to provide an initial security context on the first database
 * object exogenously, something like a seed.
 *
 * Also note that this mechanism is different from the mechanism to assign
 * a default security context. The template1 database is created in the
 * bootstraping phase without any security context. At that time, it is
 * not labeled yet. Next, initdb gives several queries to the postgresql
 * server process in single-user mode.
 * Under the initialization with single-user mode, initdb relabels the
 * template1 database using the result of this function.
 */
Datum
sepgsql_template1_getcon(PG_FUNCTION_ARGS)
{
	char   *policy_type;
	char   *context = NULL;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux support is now disabled")));

	/*
	 * At the initdb phase, all the database objects are unlabeled, so we
	 * cannot compute a default security context based on the unlabeled
	 * objects.
	 * SELinux has a configuration file to suggest an appropriate security
	 * context to be assigned on root of the default security context.
	 * We picks up it from:
	 *   /etc/selinux/${POLICY_TYPE}/contexts/sepgsql_contexts
	 *
	 * A legacy version of security policy does not have this configuration.
	 * In this case, we apply an fallbacked behavior.
	 */
	if (selinux_getpolicytype(&policy_type) == 0)
	{
		char	lineBuf[1024], classBuf[1024], nameBuf[1024], seconBuf[1024];
		char	filename[MAXPGPATH];
		char   *temp;
		FILE   *filp;

		snprintf(filename, sizeof(filename),
				 "%s%s/contexts/sepgsql_contexts",
				 selinux_path(), policy_type);

		filp = AllocateFile(filename, PG_BINARY_R);
		if (filp)
		{
			while (fgets(lineBuf, sizeof(lineBuf), filp) != NULL)
			{
				temp = strchr(lineBuf, '#');
				if (temp)
					*temp = '\0';

				if (sscanf(lineBuf, "%s %s %s",
						   classBuf, nameBuf, seconBuf) == 3
					&& strcmp(classBuf, "db_database") == 0
					&& fnmatch(nameBuf, "template1", 0) == 0)
				{
					context = pstrdup(seconBuf);
					break;
				}
			}
			FreeFile(filp);
		}
	}

	/*
	 * If configuration file is not found, or no valid security context
	 * was found, we compute a security context to be applied on the
	 * "template1" database with a fallback way.
	 */
	if (!context || security_check_context(context) < 0)
		context = sepgsql_compute_create(sepgsql_get_client_context(),
										 sepgsql_get_client_context(),
										 SEPG_CLASS_DB_DATABASE);

	context = sepgsql_mcstrans_out(context);

	PG_RETURN_TEXT_P(cstring_to_text(context));
}

/*
 * sepgsql_default_getcon
 *
 * It returns a default security context on a pair of security contexts
 * and object class.
 *
 * ARG0(text) : A security context of the subject
 * ARG1(text) : A security context of the object
 * ARG2(text) : Name of the object class
 */
Datum
sepgsql_default_getcon(PG_FUNCTION_ARGS)
{
	char   *scontext = TextDatumGetCString(PG_GETARG_TEXT_P(0));
	char   *tcontext = TextDatumGetCString(PG_GETARG_TEXT_P(1));
	char   *tclass_name = TextDatumGetCString(PG_GETARG_TEXT_P(2));
	char   *ncontext;
	int		index;

	if (!sepgsql_is_enabled())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("SELinux support is now disabled")));

	scontext = sepgsql_mcstrans_in(scontext);
	if (security_check_context_raw(scontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("Invalid security context \"%s\"", scontext)));

	tcontext = sepgsql_mcstrans_in(tcontext);
	if (security_check_context_raw(tcontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_SECURITY_CONTEXT),
				 errmsg("Invalid security context \"%s\"", scontext)));

	for (index = 0; index < SEPG_CLASS_MAX; index++)
	{
		if (strcmp(tclass_name, selinux_catalog[index].class_name) == 0)
		{
			uint16	tclass = selinux_catalog[index].class_code;

			ncontext = sepgsql_compute_create(scontext, tcontext, tclass);

			ncontext = sepgsql_mcstrans_out(ncontext);

			PG_RETURN_TEXT_P(cstring_to_text(ncontext));
		}
	}
	ereport(ERROR,
			(errcode(ERRCODE_SELINUX_ERROR),
			 errmsg("unknown object class \"%s\"", tclass_name)));
	PG_RETURN_VOID();	/* be compiler quiet */
}
