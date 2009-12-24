/*
 * src/backend/security/sepgsql/selinux.c
 *   Routines to communicate with SELinux.
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/hash.h"
#include "access/xact.h"
#include "catalog/pg_security.h"
#include "lib/stringinfo.h"
#include "libpq/libpq-be.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "storage/fd.h"
#include "utils/builtins.h"
#include "utils/memutils.h"

#include <unistd.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>

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
			{"create",			SEPG_FILE__CREATE },
			{"getattr",			SEPG_FILE__GETATTR },
			{NULL, 0}
		}
	},
	{
		"dir",					SEPG_CLASS_DIR,
		{
			{"read",			SEPG_DIR__READ },
			{"write",			SEPG_DIR__WRITE },
			{"create",			SEPG_DIR__CREATE },
			{"getattr",			SEPG_DIR__GETATTR },
			{NULL,0}
		}
	},
	{
		"lnk_file",				SEPG_CLASS_LNK_FILE,
		{
			{"read",			SEPG_LNK_FILE__READ },
			{"write",			SEPG_LNK_FILE__WRITE },
			{"create",			SEPG_LNK_FILE__CREATE },
			{"getattr",			SEPG_LNK_FILE__GETATTR },
			{NULL,0}
		}
	},
	{
		"chr_file",				SEPG_CLASS_CHR_FILE,
		{
			{"read",			SEPG_CHR_FILE__READ },
			{"write",			SEPG_CHR_FILE__WRITE },
			{"create",			SEPG_CHR_FILE__CREATE },
			{"getattr",			SEPG_CHR_FILE__GETATTR },
			{NULL,0}
		}
	},
	{
		"blk_file",				SEPG_CLASS_BLK_FILE,
		{
			{"read",			SEPG_BLK_FILE__READ },
			{"write",			SEPG_BLK_FILE__WRITE },
			{"create",			SEPG_BLK_FILE__CREATE },
			{"getattr",			SEPG_BLK_FILE__GETATTR },
			{NULL,0}
		}
	},
	{
		"sock_file",			SEPG_CLASS_SOCK_FILE,
		{
			{"read",			SEPG_SOCK_FILE__READ },
			{"write",			SEPG_SOCK_FILE__WRITE },
			{"create",			SEPG_SOCK_FILE__CREATE },
			{"getattr",			SEPG_SOCK_FILE__GETATTR },
			{NULL,0}
		}
	},
	{
		"fifo_file",			SEPG_CLASS_FIFO_FILE,
		{
			{"read",			SEPG_FIFO_FILE__READ },
			{"write",			SEPG_FIFO_FILE__WRITE },
			{"create",			SEPG_FIFO_FILE__CREATE },
			{"getattr",			SEPG_FIFO_FILE__GETATTR },
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
			{ "load_module",	SEPG_DB_DATABASE__LOAD_MODULE },
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
			{ NULL, 0UL },
		}
	},
	{
		"db_view",				SEPG_CLASS_DB_VIEW,
		{
			{ "create",			SEPG_DB_VIEW__CREATE },
			{ "drop",			SEPG_DB_VIEW__DROP },
			{ "getattr",		SEPG_DB_VIEW__GETATTR },
			{ "setattr",		SEPG_DB_VIEW__SETATTR },
			{ "relabelfrom",	SEPG_DB_VIEW__RELABELFROM },
			{ "relabelto",		SEPG_DB_VIEW__RELABELTO },
			{ "usage",			SEPG_DB_VIEW__USAGE },
			{ NULL, 0UL }
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
 * userspace access vector cache
 *
 * It enables to cache access control decisions in userspace, and minimize
 * the number of system call invocations.
 */
static MemoryContext AvcMemCtx = NULL;

#define AVC_HASH_NUM_SLOTS		256
#define AVC_HASH_NUM_NODES		180

typedef struct _avc_datum
{
	uint32			hash_key;

	uint16			tclass;
	sepgsql_sid_t	tsid;
	sepgsql_sid_t	nsid;
	char		   *tcontext;
	char		   *ncontext;

	uint32			allowed;
	uint32			auditallow;
	uint32			auditdeny;
	bool			permissive;

	bool			hot_cache;
} avc_datum;

typedef struct _avc_page
{
	struct _avc_page	   *next;

	List	   *slot[AVC_HASH_NUM_SLOTS];

	uint32		avc_count;
	uint32		lru_hint;

	char		scontext[1];
} avc_page;

static avc_page	   *current_page = NULL;

static int			avc_version;

/*
 * selinux_state
 *
 * It is deployed on the shared memory region, to show the system
 * state of SELinux and its security policy.
 *
 * The selinux_state->version should be checked prior to avc accesses.
 * If it does not match with the local avc_version, it means that
 * system security policy was reloaded or system state (enforcing
 * or permissive) was changed.
 *
 * The state monitoring worker process receives messages from the
 * kernel using libselinux, and it updates the selinux_state.
 */
struct
{
	int			version;

	bool		enforcing;
}  *selinux_state = NULL;

/*
 * sepgsqlShmemSize
 *
 * It returns required size for shared memory segment
 */
Size
sepgsqlShmemSize(void)
{
	if (!sepgsqlIsEnabled())
		return 0;

	return sizeof(*selinux_state);
}

/*
 * sepgsqlShmemInit
 *
 * It attaches shared memory segment.
 */
static void
sepgsqlShmemInit(void)
{
	bool	found;

	selinux_state = ShmemInitStruct("SELinux system state",
									sepgsqlShmemSize(), &found);
	if (!found)
	{
		LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);

		selinux_state->version = 0;
		selinux_state->enforcing = (security_getenforce() > 0);

		LWLockRelease(SepgsqlAvcLock);
	}
}

/*
 * sepgsqlIsEnabled
 * sepgsqlIsEnabledBootstrap
 *
 * If it returns true, SE-PgSQL is enabled. Otherwise, it is disabled.
 */
bool
sepgsqlIsEnabledBootstrap(void)
{
	static int	enabled = -1;

	/*
	 * If sepostgresql = off, it is always disabled.
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

bool
sepgsqlIsEnabled(void)
{
	/*
	 * SE-PgSQL is not ready in bootstraping mode,
	 * except for initial labeling process 
	 */
	if (IsBootstrapProcessingMode())
		return false;

	return sepgsqlIsEnabledBootstrap();
}

/*
 * sepgsqlGetEnforce
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
sepgsqlGetEnforce(void)
{
	if (sepostgresql_mode == SEPGSQL_MODE_DEFAULT)
	{
		bool	rc;

		LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
		rc = selinux_state->enforcing;
		LWLockRelease(SepgsqlAvcLock);

		return rc;
	}
	else if (sepostgresql_mode == SEPGSQL_MODE_ENFORCING)
		return true;

	return false;
}

/*
 * sepgsqlShowMode
 *
 * It returns the current performing mode ('selinux_support')
 * in human readable form.
 */
char *
sepgsqlShowMode(void)
{
	if (!sepgsqlIsEnabled())
		return "disabled";

	if (!sepgsqlGetEnforce())
		return "permissive";

	return "enforcing";
}

/*
 * sepgsqlGetClientLabel
 * sepgsqlSetClientLabel
 * sepgsqlGetServerLabel
 */
static char *clientLabel = NULL;

char *
sepgsqlGetClientLabel(void)
{
	if (clientLabel)
		return clientLabel;

	if (!MyProcPort)
	{
		/*
		 * When this server process was launched in single-user mode,
		 * it does not have any client socket, and the server process also
		 * performs as a client in same time. So, we apply a security context
		 * of the current process as a client's one.
		 * The getcon_raw(3) is an libselinux API to obtain security context
		 * of the current process in raw format.
		 */
		if (getprevcon_raw(&clientLabel) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("could not get server's security context")));
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
		if (getpeercon_raw(MyProcPort->sock, &clientLabel) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("could not get client's security context")));
	}
	return clientLabel;
}

char *
sepgsqlSetClientLabel(char *new_label)
{
	char		   *old_label = clientLabel;
	avc_page	   *new_page;
	int				i, length;

	/*
	 * (1) Set new security context
	 */
	clientLabel = new_label;

	/*
	 * (2) Switch current AVC page
	 */
	if (current_page)
	{
		new_page = current_page;
		do {
			if (strcmp(new_page->scontext, new_label) == 0)
			{
				current_page = new_page;
				return old_label;
			}
			new_page = new_page->next;
		} while (new_page != current_page);
	}

	/* Not found, create a new avc_page */
	length = sizeof(avc_page) + strlen(new_label);
	new_page = MemoryContextAllocZero(AvcMemCtx, length);

	strcpy(new_page->scontext, new_label);
	for (i=0; i < AVC_HASH_NUM_SLOTS; i++)
		new_page->slot[i] = NIL;

	if (!current_page)
		new_page->next = new_page;
	else
	{
		new_page->next = current_page->next;
		current_page->next = new_page;
	}

	current_page = new_page;

	/* return old label */
	return old_label;
}

char *
sepgsqlGetServerLabel(void)
{
	static char *serverLabel = NULL;

	if (!serverLabel)
	{
		if (getcon_raw(&serverLabel) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("could not get server's security context")));
	}
	return serverLabel;
}

/*
 * sepgsqlAuditLog
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
static void
sepgsqlAuditLog(bool denied, char *scontext, char *tcontext,
				  uint16 tclass, uint32 audited, const char *audit_name)
{
	//static int		auditfd = -2;
	StringInfoData	buf;
	const char	   *tclass_name;
	const char	   *perm_name;
	int				i;

	/*
	 * translation of security contexts to human readable format,
	 * if sepgsql_mcstrans is turned on.
	 */
	scontext = sepgsqlTransSecLabelOut(scontext);
	tcontext = sepgsqlTransSecLabelOut(tcontext);

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

	appendStringInfo(&buf, " scontext=%s tcontext=%s tclass=%s",
					 scontext, tcontext, tclass_name);
	if (audit_name)
		appendStringInfo(&buf, " name=%s", audit_name);

	ereport(LOG,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 errmsg("SELinux: %s %s",
					(denied ? "denied" : "allowed"), buf.data)));
}

/*
 * computePermsInternal
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
computePermsInternal(char *scontext, char *tcontext,
					 uint16 tclass, struct av_decision *avd)
{
	const char		   *tclass_name;
	security_class_t	tclass_ex;
	struct av_decision	avd_ex;
	int					i, deny_unknown = security_deny_unknown();

	/* Get external code of the object class*/
	Assert(tclass < SEPG_CLASS_MAX);
	Assert(tclass == selinux_catalog[tclass].class_code);

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
 * sepgsqlComputePerms
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
sepgsqlComputePerms(char *scontext, char *tcontext,
					uint16 tclass, uint32 required,
					const char *audit_name, bool abort)
{
	struct av_decision	avd;
	uint32		denied;
	uint32		audited;

	computePermsInternal(scontext, tcontext, tclass, &avd);

	/*
	 * It logs a security audit record for the given request, if necessary.
	 * When SE-PgSQL performs 'internal' mode, it needs to keep silent.
	 */
	denied = required & ~avd.allowed;
	audited = denied ? (denied & avd.auditdeny)
					 : (required & avd.auditallow);

	if (audited && sepostgresql_mode != SEPGSQL_MODE_INTERNAL)
	{
		sepgsqlAuditLog(!!denied, scontext, tcontext,
						tclass, audited, audit_name);
	}

	/*
	 * If here is no policy violations, or SE-PgSQL performs in permissive
	 * mode, or the client process peforms in permissive domain, it returns
	 * normally with 'true'.
	 */
	if (!denied ||
		!sepgsqlGetEnforce() ||
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
 * sepgsqlComputeCreate
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
sepgsqlComputeCreate(char *scontext, char *tcontext, uint16 tclass)
{
	security_context_t	ncontext;
	security_class_t	tclass_ex;
	const char		   *tclass_name;
	char			   *result;

	/* Get external code of the object class*/
	Assert(tclass < SEPG_CLASS_MAX);
	Assert(tclass == selinux_catalog[tclass].class_code);

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
 * sepgsqlAvcReset
 *
 * Invalidate all the cached access control decision
 */
static void
sepgsqlAvcReset(void)
{
	Assert(AvcMemCtx != NULL);

	MemoryContextReset(AvcMemCtx);

	current_page = NULL;

	sepgsqlSetClientLabel(sepgsqlGetClientLabel());
}

static void
sepgsqlAvcResetOnAbort(XactEvent event, void *arg)
{
	if (event == XACT_EVENT_ABORT)
		sepgsqlAvcReset();
}

static void
sepgsqlAvcResetOnSubAbort(SubXactEvent event, SubTransactionId mySubid,
						  SubTransactionId parentSubid, void *arg)
{
	if (event == SUBXACT_EVENT_ABORT_SUB)
		sepgsqlAvcReset();
}

/*
 * sepgsqlAvcCheckValid
 *
 * It checks whether the current AVC pages are valid, or not.
 */
static bool
sepgsqlAvcCheckValid(void)
{
	bool result = true;

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	if (avc_version != selinux_state->version)
	{
		sepgsqlAvcReset();

		/* Copy the current version to local */
		avc_version = selinux_state->version;

		result = false;
	}
	LWLockRelease(SepgsqlAvcLock);

	return result;
}

/*
 * sepgsqlAvcReclaim
 *
 * It wipes recently unused AVC entries, if necessary.
 */
static void
sepgsqlAvcReclaim(avc_page *page)
{
	ListCell   *l;
	avc_datum  *cache;

	while (page->avc_count > AVC_HASH_NUM_NODES - 10)
	{
		foreach (l, page->slot[page->lru_hint])
		{
			cache = lfirst(l);

			if (cache->hot_cache)
				cache->hot_cache = false;
			else
			{
				list_delete_ptr(page->slot[page->lru_hint], cache);
				pfree(cache);
				page->avc_count--;
			}
		}
		page->lru_hint = (page->lru_hint + 1) % AVC_HASH_NUM_SLOTS;
	}
}

/*
 * sepgsqlAvcMakeEntry
 *
 * It makes a new avc entry, and insert it to the given page.
 */
#define avc_hash_key(trelid, tsecid, tclass, nrelid)	\
	(hash_uint32((trelid) ^ (tsecid) ^ ((tclass) << 3) ^ (nrelid)))

static avc_datum *
sepgsqlAvcMakeEntry(avc_page *page, sepgsql_sid_t tsid, uint16 tclass, Oid nrelid)
{
	MemoryContext	oldctx;
	char	   *scontext;
	char	   *tcontext;
	char	   *ncontext;
	avc_datum  *cache;
	uint32		hash_key, index;

	hash_key = avc_hash_key(tsid.relid, tsid.secid, tclass, nrelid);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	oldctx = MemoryContextSwitchTo(AvcMemCtx);

	scontext = page->scontext;
	tcontext = securityRawSecLabelOut(tsid.relid, tsid.secid);
	ncontext = sepgsqlComputeCreate(scontext, tcontext, tclass);

	cache = palloc0(sizeof(avc_datum));

	cache->hash_key = hash_key;

	cache->tclass = tclass;

	cache->hot_cache = true;
	cache->tcontext = tcontext;
	cache->ncontext = ncontext;
	cache->tsid.relid = tsid.relid;
	cache->tsid.secid = tsid.secid;
	cache->nsid.relid = nrelid;

	if (OidIsValid(nrelid))
		cache->nsid.secid = securityRawSecLabelIn(nrelid, ncontext);
	else
		cache->nsid.secid = InvalidOid;

	if (!OidIsValid(nrelid))
	{
		struct av_decision	avd;

		computePermsInternal(scontext, tcontext, tclass, &avd);
		cache->allowed = avd.allowed;
		cache->auditallow = avd.auditallow;
		cache->auditdeny = avd.auditdeny;

		if (avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE)
			cache->permissive = true;
	}

	if (page->avc_count > AVC_HASH_NUM_NODES)
		sepgsqlAvcReclaim(page);

	page->slot[index] = lcons(cache, page->slot[index]);
	page->avc_count++;

	MemoryContextSwitchTo(oldctx);

	return cache;
}

/*
 * sepgsqlAvcLookup
 *
 * It lookups required AVC entry
 */
static avc_datum *
sepgsqlAvcLookup(avc_page *page, sepgsql_sid_t tsid, uint16 tclass, Oid nrelid)
{
	avc_datum  *cache = NULL;
	uint32		hash_key, index;
	ListCell   *l;

	hash_key = avc_hash_key(tsid.relid, tsid.secid, tclass, nrelid);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	foreach (l, page->slot[index])
	{
		cache = lfirst(l);
		if (cache->hash_key == hash_key &&
			cache->tclass == tclass &&
			cache->tsid.relid == tsid.relid &&
			cache->tsid.secid == tsid.secid &&
			cache->nsid.relid == nrelid)
		{
			cache->hot_cache = true;
			return cache;
		}
	}
	return NULL;
}

/*
 * sepgsqlClientHasPerms
 *
 * It checks client's privileges on the given object using avc.
 */
bool
sepgsqlClientHasPerms(sepgsql_sid_t tsid,
					  uint16 tclass, uint32 required,
					  const char *audit_name, bool abort)
{
    avc_datum      *cache;
    uint32          denied, audited;
    bool            result = true;

	do {
		cache = sepgsqlAvcLookup(current_page, tsid, tclass, InvalidOid);
		if (!cache)
			cache = sepgsqlAvcMakeEntry(current_page, tsid, tclass, InvalidOid);
	} while (!sepgsqlAvcCheckValid());

	denied = required & ~cache->allowed;
	audited = denied ? (denied & cache->auditdeny)
		: (required & cache->auditallow);
	if (audited)
	{
		sepgsqlAuditLog(!!denied,
						current_page->scontext,
						securityRawSecLabelOut(tsid.relid, tsid.secid),
						cache->tclass, audited, audit_name);
	}

	if (denied)
	{
		if (!sepgsqlGetEnforce() || cache->permissive)
			cache->allowed |= required;     /* prevent flood of audit log */
		else
		{
			if (abort)
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("SELinux: security policy violation")));
			result = false;
		}
	}

	return result;
}

/*
 * sepgsqlClientCreateSecid
 * sepgsqlClientCreateLabel
 */
sepgsql_sid_t
sepgsqlClientCreateSecid(sepgsql_sid_t tsid, uint16 tclass, Oid nrelid)
{
	avc_datum      *cache;

	do {
		cache = sepgsqlAvcLookup(current_page, tsid, tclass, nrelid);
		if (!cache)
			cache = sepgsqlAvcMakeEntry(current_page, tsid, tclass, nrelid);
	} while (!sepgsqlAvcCheckValid());

	return cache->nsid;
}

security_context_t
sepgsqlClientCreateLabel(sepgsql_sid_t tsid, uint16 tclass)
{
    avc_datum  *cache;

    do {
        cache = sepgsqlAvcLookup(current_page, tsid, tclass, InvalidOid);
        if (!cache)
            cache = sepgsqlAvcMakeEntry(current_page, tsid, tclass, InvalidOid);
    } while (!sepgsqlAvcCheckValid());

    return cache->ncontext;
}

/*
 * SELinux state monitoring process
 *
 * This process is forked from postmaster to monitor the state of SELinux.
 * SELinux can make a notifier message to userspace object manager via
 * netlink socket. When it receives the message, it updates selinux_state
 * structure assigned on shared memory region to make any instance reset
 * its AVC soon.
 */
static int
sepgsql_cb_log(int type, const char *fmt, ...)
{
	char *c, buffer[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	c = strrchr(buffer, '\n');
	if (c)
		*c = '\0';

	ereport(LOG,(errmsg("%s", buffer)));

	return 0;
}

static int
sepgsql_cb_setenforce(int enforce)
{
	/* switch enforcing/permissive */
	LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
	selinux_state->enforcing = (enforce ? true : false);
	selinux_state->version++;
	LWLockRelease(SepgsqlAvcLock);

	return 0;
}

static int
sepgsql_cb_policyload(int seqno)
{
	/* invalidate local avc */
	LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
	selinux_state->version++;
	LWLockRelease(SepgsqlAvcLock);

	return 0;
}

bool
sepgsqlReceiverStart(void)
{
	return sepgsqlIsEnabled();
}

void
sepgsqlReceiverMain(void)
{
	union selinux_callback cb;

	Assert(sepgsqlIsEnabled());

#ifdef HAVE_SETSID
	if (setsid() < 0)
		elog(FATAL, "setsid() failed: %m");
#endif

	/*
	 * setup the signal handler
	 */
	pqinitmask();
	pqsignal(SIGHUP, SIG_IGN);
	pqsignal(SIGINT, SIG_IGN);
	pqsignal(SIGTERM, exit);
	pqsignal(SIGQUIT, exit);
	pqsignal(SIGUSR1, SIG_IGN);
	pqsignal(SIGUSR2, SIG_IGN);
	pqsignal(SIGCHLD, SIG_DFL);
	PG_SETMASK(&UnBlockSig);

	/*
	 * map shared memory segment
	 */
	sepgsqlShmemInit();

	ereport(LOG, (errmsg("SELinux: netlink receiver (pid=%u)", getpid())));

	/*
	 * setup callback functions from avc_netlink_loop()
	 */
	cb.func_log = sepgsql_cb_log;
	selinux_set_callback(SELINUX_CB_LOG, cb);
	cb.func_setenforce = sepgsql_cb_setenforce;
	selinux_set_callback(SELINUX_CB_SETENFORCE, cb);
	cb.func_policyload = sepgsql_cb_policyload;
	selinux_set_callback(SELINUX_CB_POLICYLOAD, cb);

	/*
	 * open netlink socket and wait for messages
	 */
	avc_netlink_open(1);

	avc_netlink_loop();

	exit(0);
}

/*
 * sepgsqlInitialize
 *
 * It sets up the privilege (security context) of the client and initializes
 * a few internal stuff.
 */
void
sepgsqlInitialize(void)
{
	if (!sepgsqlIsEnabled())
		return;

	/*
	 * SE-PgSQL does not prevent anything in single-user mode.
	 */
	if (!MyProcPort)
		sepostgresql_mode = SEPGSQL_MODE_INTERNAL;

	sepgsqlShmemInit();

	AvcMemCtx = AllocSetContextCreate(TopMemoryContext,
									  "SE-PgSQL userspace AVC",
									  ALLOCSET_DEFAULT_MINSIZE,
									  ALLOCSET_DEFAULT_INITSIZE,
									  ALLOCSET_DEFAULT_MAXSIZE);

	RegisterXactCallback(sepgsqlAvcResetOnAbort, NULL);
	RegisterSubXactCallback(sepgsqlAvcResetOnSubAbort, NULL);

	/*
	 * Set client's security context
	 */
	sepgsqlSetClientLabel(sepgsqlGetClientLabel());
}
