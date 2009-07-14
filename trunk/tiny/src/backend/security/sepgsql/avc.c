/*
 * src/backend/security/sepgsql/avc.c
 *    SE-PostgreSQL userspace access vector cache
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

/******************/


PGDLLIMPORT sepgsqlAvcAuditHook_t sepgsqlAvcAuditHook;

/*********/
bool
sepgsqlClientHasPermsTup(Oid relid, HeapTuple tuple,
						 uint16 tclass, uint32 required, bool abort)
{
	Datum	datum;
	bool	isnull;
	char   *seclabel = NULL;

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

	return sepgsqlComputePerms(sepgsqlGetClientLabel(),
							   seclabel, tclass, required, abort);
}

/*********/
bool
sepgsqlClientHasPermsLabel(Oid relid, const char *seclabel,
						   uint16 tclass, uint32 required, bool abort)
{}

/*
 * sepgsqlComputePerms
 *
 *
 *
 *
 *
 *
 */
bool
sepgsqlComputePerms(const char *scontext, const char *tcontext,
					uint16 tclass_in, uint32 required, bool abort)
{
	access_vector_t		denied, audited;
	security_class_t	tclass_ex;
	struct av_decision	avd;

	Assert(required != 0);

	tclass_ex = sepgsqlTransToExternalClass(tclass_in);
	if (tclass_ex > 0)
	{
		if (security_compute_av_flags_raw(scontext, tcontext,
										  tclass_ex, 0, &avd) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: could not compute av_decision: "
							"scontext=%s tcontext=%s tclass=%s",
							scontext, tcontext,
							sepgsqlGetClassString(tclass))));
		sepgsqlTransToInternalPerms(tclass_in, &avd);
	}
	else
	{
		/* fill it up as undefined class */
		avd.allowed = (security_deny_unknown() ? 0 : ~0UL);
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
		avc_audit_common(sepgsqlTransSecLabelOut(scontext),
						 sepgsqlTransSecLabelOut(tcontext),
						 tclass, !!denied, audited, audit_name);
	}

	if (denied && security_getenforce() < 1 &&
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

/*********/
char *
sepgsqlComputeCreate(const char *scontext, const char *tcontext,
					 uint16 tclass_in)
{
	security_context_t	ncontext, result;
	security_class_t	tclass_ex;

	tclass_ex = sepgsqlTransToExternalClass(tclass_in);
	if (security_compute_create_raw(scontext, tcontext,
									tclass_ex, &ncontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute a new context ",
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
