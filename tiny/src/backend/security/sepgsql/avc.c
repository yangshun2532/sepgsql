/*
 * src/backend/security/sepgsql/avc.c
 *    SE-PostgreSQL makes its access control decision
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "security/sepgsql.h"
#include "utils/builtins.h"
#include "utils/syscache.h"

/*
 * sepgsqlAvcInitialize
 *
 * If the current backend is not associated with a certain
 * client process, it switches to permissive mode to avoid
 * to prevent any internal processes.
 */
void
sepgsqlAvcInitialize(void)
{
	if (!sepgsqlIsEnabled())
		return;

	/*
	 * Switch to local permissive mode,
	 * if the backend is not assigned to a certain client.
	 */
	if (!MyProcPort)
		sepgsqlSetEnforce(0);
}

/*
 * sepgsqlGetEnforce
 * sepgsqlSetEnforce
 *
 * SELinux has two working mode called Enforcing/Permissive.
 * In enforcing mode, it checks security policy and actually
 * applies its access controls. In permissive mode, it also
 * checks security policy, but does not apply any access
 * controls. It is used to collect access denied logs to
 * debug security policy.
 *
 * sepgsqlGetEnforce() returns the current working mode, and
 * sepgsqlSetEnforce() switches the current working mode
 * temporary. When we switches the mode, any errors have to
 * be acquired, and it should be restored correctly.
 */
static int	local_enforce = -1;	/* undefined */

bool
sepgsqlGetEnforce(void)
{
	/* Enforcing mode, independent from system setting */
	if (local_enforce > 0)
		return true;

	/* Permissive mode independent from system setting */
	if (local_enforce == 0)
		return false;

	/* According to the system setting */
	return (security_getenforce() > 0 ? true : false);
}

int
sepgsqlSetEnforce(int new_mode)
{
	int		old_mode = local_enforce;

	local_enforce = new_mode;

	return old_mode;
}

/*
 * sepgsqlAvcAudit
 *
 * It write out audit message, when auditdeny or auditallow
 * matches the required permission bits.
 * If external module support sepgsqlAvcAuditHook, it allows
 * to write audit logs to external log manager, such as system
 * auditd.
 */

PGDLLIMPORT sepgsqlAvcAuditHook_t sepgsqlAvcAuditHook = NULL;

static void
sepgsqlAvcAudit(bool denied, char *scontext, char *tcontext,
				uint16 tclass, uint32 audited, const char *audit_name)
{
	StringInfoData	buf;
	uint32			mask;
	const char	   *tclass_name;

	/* translate to human readable form */
	scontext = sepgsqlTransSecLabelOut(scontext);
	tcontext = sepgsqlTransSecLabelOut(tcontext);

	/* permissions in text representation */
	initStringInfo(&buf);
	appendStringInfo(&buf, "{");
	for (mask = 1; audited != 0; mask <<= 1)
	{
		if (audited & mask)
			appendStringInfo(&buf, " %s", sepgsqlGetPermString(tclass, mask));

		audited &= ~mask;
	}
	appendStringInfo(&buf, " }");

	tclass_name = sepgsqlGetClassString(tclass);

	/* call external audit module, if loaded */
	if (sepgsqlAvcAuditHook)
		(*sepgsqlAvcAuditHook) (denied, scontext, tcontext,
								tclass_name, buf.data, audit_name);
	else
	{
		appendStringInfo(&buf, " scontext=%s tcontext=%s tclass=%s",
						 scontext, tcontext, tclass_name);
		if (audit_name)
			appendStringInfo(&buf, " name=%s", audit_name);

		ereport(LOG,
				(errcode(ERRCODE_SELINUX_AUDIT),
				 errmsg("SELinux: %s %s",
						denied ? "denied" : "granted", buf.data)));
	}
}

/*
 * sepgsqlClientHasPermsTup
 *
 * A wrapper function to sepgsqlComputePerms()
 */
bool
sepgsqlClientHasPermsTup(Oid relid, HeapTuple tuple,
						 uint16 tclass, uint32 required, bool abort)
{
	Datum		datum;
	bool		isnull;
	char	   *seclabel = NULL;
	const char *audit_name = sepgsqlAuditName(relid, tuple);

	switch (relid)
	{
	case DatabaseRelationId:
		datum = SysCacheGetAttr(DATABASEOID, tuple,
								Anum_pg_database_datseclabel, &isnull);
		if (!isnull)
			seclabel = TextDatumGetCString(datum);
		break;

	case NamespaceRelationId:
		datum = SysCacheGetAttr(NAMESPACEOID, tuple,
								Anum_pg_namespace_nspseclabel, &isnull);
		if (!isnull)
			seclabel = TextDatumGetCString(datum);
		break;

	case ProcedureRelationId:
		datum = SysCacheGetAttr(PROCOID, tuple,
								Anum_pg_proc_proseclabel, &isnull);
		if (!isnull)
			seclabel = TextDatumGetCString(datum);
		break;

	default:
		/* unlabeled context */
		break;
	}
	/* validate security context */
	seclabel = sepgsqlRawSecLabelOut(seclabel);

	return sepgsqlComputePerms(sepgsqlGetClientLabel(), seclabel,
							   tclass, required, audit_name, abort);
}

/*
 * sepgsqlClientCreateLabel
 *
 * A wrapper function to sepgsqlComputeCreate
 */
char *
sepgsqlClientCreateLabel(char *tcontext, uint16 tclass)
{
	return sepgsqlComputeCreate(sepgsqlGetClientLabel(),
								tcontext, tclass);
}

/*
 * sepgsqlComputePerms
 *
 * It tells in-kernel SELinux whether the given combination of
 * client's label (scontext), target object's label (tcontext)
 * and kind of actions (tclass_in and required) should be allowed
 * or not.
 * If all the required permissions are allowed, it returns true.
 * Otherwise, it returns false or raises an error.
 */
bool
sepgsqlComputePerms(char *scontext, char *tcontext,
					uint16 tclass_in, uint32 required,
					const char *audit_name, bool abort)
{
	access_vector_t		denied, audited;
	security_class_t	tclass_ex;
	struct av_decision	avd;

	Assert(required != 0);

	tclass_ex = sepgsqlTransToExternalClass(tclass_in);
	if (tclass_ex > 0)
	{
		/*
		 * security_compute_av_flags_raw() is a SELinux's API that
		 * returns its access control decision based on the security
		 * policy, to the given combination of user's privilege
		 * (scontext; security label of the client process),
		 * target's attribute (tcontext; security label of the
		 * object) and type of actions (tclass; object classes).
		 *
		 * The returned avd.allowed is a bitmap of allowed actions.
		 */
		if (security_compute_av_flags_raw(scontext, tcontext,
										  tclass_ex, 0, &avd) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not compute av_decision: "
							"scontext=%s tcontext=%s tclass=%s",
							scontext, tcontext,
							sepgsqlGetClassString(tclass_in))));
		sepgsqlTransToInternalPerms(tclass_in, &avd);
	}
	else
	{
		/*
		 * If security policy does not support database related
		 * permissions, it fulls up permission bits by dummy
		 * data.
		 * If security_deny_unknown() returns positive value,
		 * undefined permissions should not be allowed.
		 * Otherwise, it shall be allowed.
		 */
		avd.allowed = (security_deny_unknown() > 0 ? 0 : ~0UL);
		avd.decided = ~0UL;
		avd.auditallow = 0UL;
		avd.auditdeny = ~0UL;
		avd.flags = 0;
	}

	denied = required & ~avd.allowed;
	audited = denied ? (denied & avd.auditdeny)
					 : (required & avd.auditallow);
	if (audited)
	{
		/*
		 * If security policy requires to generate an audit log
		 * record for the given request, it should be logged.
		 */
		sepgsqlAvcAudit(!!denied, scontext, tcontext,
						tclass_in, audited, audit_name);
	}

	/*
	 * If any required permissions are not allowed, and
	 * SE-PgSQL performs in enforcing mode, and the given
	 * combination of subject, object and action does not
	 * have special flag to be handled as permission,
	 * SE-PgSQL returns false or raises an error.
	 * Otherwise, it returns true that means required
	 * actions are allowed.
	 */
	if (denied && sepgsqlGetEnforce() &&
		(avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE) == 0)
	{
		if (abort)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: security policy violation")));
		return false;
	}

	return true;
}

/*
 * sepgsqlComputeCreate
 *
 * It tells in-kernel SELinux a default security label to be assigned
 * on the new tclass_in type object under tcontext, by scontext.
 */
char *
sepgsqlComputeCreate(char *scontext, char *tcontext, uint16 tclass_in)
{
	security_context_t	ncontext, result;
	security_class_t	tclass_ex;

	tclass_ex = sepgsqlTransToExternalClass(tclass_in);
	/*
	 * security_compute_create_raw() is a SELinux's API that
	 * returns a default security context to be assigned on
	 * a new object (categorized by object class) when a client
	 * labeled as scontext tries to create a new one under the
	 * parent object labeled as tcontext.
	 */
	if (security_compute_create_raw(scontext, tcontext,
									tclass_ex, &ncontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute a new context "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsqlGetClassString(tclass_in))));
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
