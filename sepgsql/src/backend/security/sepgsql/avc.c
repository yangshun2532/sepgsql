/*
 * src/backend/security/sepgsql/avc.c
 *   SE-PostgreSQL userspace access vector cache,
 *
 * Copyright (c) 2008 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "access/hash.h"
#include "libpq/pqsignal.h"
#include "postmaster/postmaster.h"
#include "security/pgace.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "utils/memutils.h"
#include "utils/syscache.h"
#include <linux/netlink.h>
#include <linux/selinux_netlink.h>
#include <signal.h>
#include <unistd.h>

static struct {
	struct {
		const char *name;
		security_class_t internal;
	} tclass;
	struct {
		char *name;
		access_vector_t internal;
	} av_perms[sizeof(access_vector_t) * 8];
} selinux_catalog[] = {
	{
		{ "db_database", SECCLASS_DB_DATABASE },
		{
			{ "create",			DB_DATABASE__CREATE },
			{ "drop",			DB_DATABASE__DROP },
			{ "getattr",		DB_DATABASE__GETATTR },
			{ "setattr",		DB_DATABASE__SETATTR },
			{ "relabelfrom",	DB_DATABASE__RELABELFROM },
			{ "relabelto",		DB_DATABASE__RELABELTO },
			{ "access",			DB_DATABASE__ACCESS },
			{ "install_module",	DB_DATABASE__INSTALL_MODULE },
			{ "load_module",	DB_DATABASE__LOAD_MODULE },
			{ "get_param",		DB_DATABASE__GET_PARAM },
			{ "set_param",		DB_DATABASE__SET_PARAM },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_table", SECCLASS_DB_TABLE },
		{
			{ "create",			DB_TABLE__CREATE },
			{ "drop",			DB_TABLE__DROP },
			{ "getattr",		DB_TABLE__GETATTR },
			{ "setattr",		DB_TABLE__SETATTR },
			{ "relabelfrom",	DB_TABLE__RELABELFROM },
			{ "relabelto",		DB_TABLE__RELABELTO },
			{ "use",			DB_TABLE__USE },
			{ "select",			DB_TABLE__SELECT },
			{ "update",			DB_TABLE__UPDATE },
			{ "insert",			DB_TABLE__INSERT },
			{ "delete",			DB_TABLE__DELETE },
			{ "lock",			DB_TABLE__LOCK },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_procedure", SECCLASS_DB_PROCEDURE },
		{
			{ "create",			DB_PROCEDURE__CREATE },
			{ "drop",			DB_PROCEDURE__DROP },
			{ "getattr",		DB_PROCEDURE__GETATTR },
			{ "setattr",		DB_PROCEDURE__SETATTR },
			{ "relabelfrom",	DB_PROCEDURE__RELABELFROM },
			{ "relabelto",		DB_PROCEDURE__RELABELTO },
			{ "execute",		DB_PROCEDURE__EXECUTE },
			{ "entrypoint",		DB_PROCEDURE__ENTRYPOINT },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_column", SECCLASS_DB_COLUMN },
		{
			{ "create",			DB_COLUMN__CREATE },
			{ "drop",			DB_COLUMN__DROP },
			{ "getattr",		DB_COLUMN__GETATTR },
			{ "setattr",		DB_COLUMN__SETATTR },
			{ "relabelfrom",	DB_COLUMN__RELABELFROM },
			{ "relabelto",		DB_COLUMN__RELABELTO },
			{ "use",			DB_COLUMN__USE },
			{ "select",			DB_COLUMN__SELECT },
			{ "update",			DB_COLUMN__UPDATE },
			{ "insert",			DB_COLUMN__INSERT },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_tuple", SECCLASS_DB_TUPLE },
		{
			{ "relabelfrom",	DB_TUPLE__RELABELFROM },
			{ "relabelto",		DB_TUPLE__RELABELTO },
			{ "use",			DB_TUPLE__USE },
			{ "select",			DB_TUPLE__SELECT },
			{ "update",			DB_TUPLE__UPDATE },
			{ "insert",			DB_TUPLE__INSERT },
			{ "delete",			DB_TUPLE__DELETE },
			{ NULL,				0UL },
		}
	},
	{
		{ "db_blob", SECCLASS_DB_BLOB },
		{
			{ "create",			DB_BLOB__CREATE },
			{ "drop",			DB_BLOB__DROP },
			{ "getattr",		DB_BLOB__GETATTR },
			{ "setattr",		DB_BLOB__SETATTR },
			{ "relabelfrom",	DB_BLOB__RELABELFROM },
			{ "relabelto",		DB_BLOB__RELABELTO },
			{ "read",			DB_BLOB__READ },
			{ "write",			DB_BLOB__WRITE },
			{ "import",			DB_BLOB__IMPORT },
			{ "export",			DB_BLOB__EXPORT },
			{ NULL,				0UL },
		}
	},
};
#define NUM_SELINUX_CATALOG (sizeof(selinux_catalog) / sizeof(selinux_catalog[0]))

static MemoryContext AvcMemCtx;

#define AVC_HASH_NUM_SLOTS		256
#define AVC_HASH_NUM_NODES		600

struct avc_datum {
	uint32 hash_key;

	security_context_t	scon;	/* source security context */
	security_context_t	tcon;	/* target security context */
	security_class_t	tclass;	/* object class number */

	security_context_t	ncon;	/* newly created security context */

	access_vector_t allowed;
	access_vector_t decided;
	access_vector_t auditallow;
	access_vector_t auditdeny;

	bool hot_cache;
};

static sig_atomic_t avc_version;
static bool avc_enforcing;
static List *avc_slot[AVC_HASH_NUM_SLOTS];
static uint32 avc_datum_count = 0;
static uint32 avc_lru_hint = 0;

/*
 * selinux_state is assigned on shared memory region.
 *
 * We can read selinux_state->version without locking,
 * but have to hold SepgsqlAvcLock to refer other members.
 */
struct {
	/* only state monitoring process can update version */
	volatile sig_atomic_t version;

	/* if enforcing = true, SELinux is in enforcing mode */
	bool enforcing;

	/* object class/permission mapping */
	struct {
		struct {
			security_class_t internal;
			security_class_t external;
		} tclass;
		struct {
			access_vector_t internal;
			access_vector_t external;
		} av_perms[sizeof(access_vector_t) * 8];
	} catalog[NUM_SELINUX_CATALOG];
} *selinux_state = NULL;

Size sepgsqlShmemSize(void)
{
	return sizeof(*selinux_state);
}

static void load_class_av_mapping(void)
{
	/* have to hold LW_EXCLUSIVE, at least */
	security_class_t tclass;
	access_vector_t av_perms;
	int i, j;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		tclass = string_to_security_class(selinux_catalog[i].tclass.name);
		if (!tclass)
			tclass = selinux_catalog[i].tclass.internal;

		selinux_state->catalog[i].tclass.internal
			= selinux_catalog[i].tclass.internal;
		selinux_state->catalog[i].tclass.external = tclass;

		for (j=0; selinux_catalog[i].av_perms[j].name; j++) {
			av_perms = string_to_av_perm(tclass, selinux_catalog[i].av_perms[j].name);
			if (!av_perms)
				av_perms = selinux_catalog[i].av_perms[j].internal;

			selinux_state->catalog[i].av_perms[j].internal
				= selinux_catalog[i].av_perms[j].internal;
			selinux_state->catalog[i].av_perms[j].external = av_perms;
		}
	}
}

static security_class_t
trans_to_external_tclass(security_class_t i_tclass)
{
	/* have to hold SepgsqlAvcLock with LW_SHARED */
	int i;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (selinux_state->catalog[i].tclass.internal == i_tclass)
			return selinux_state->catalog[i].tclass.external;
	}
	return i_tclass;	/* use it as is for kernel classes */
}

static access_vector_t
trans_to_internal_perms(security_class_t e_tclass, access_vector_t e_perms)
{
	/* have to hold SepgsqlAvcLock with LW_SHARED */
	access_vector_t i_perms = 0UL;
	int i, j;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (selinux_state->catalog[i].tclass.external != e_tclass)
			continue;
		for (j=0; j < sizeof(access_vector_t) * 8; j++) {
			if (selinux_state->catalog[i].av_perms[j].external & e_perms)
				i_perms |= selinux_state->catalog[i].av_perms[j].internal;
		}
		return i_perms;
	}
	return i_perms;		/* use it as is for kernel classes */
}

static const char *sepgsql_class_to_string(security_class_t tclass)
{
	int i;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (selinux_catalog[i].tclass.internal == tclass)
			return selinux_catalog[i].tclass.name;
	}
	/* tclass is always same as external one, for kernel object classes */
	return security_class_to_string(tclass);
}

static const char *sepgsql_av_perm_to_string(security_class_t tclass, access_vector_t perm)
{
	int i, j;

	for (i=0; i < NUM_SELINUX_CATALOG; i++) {
		if (selinux_catalog[i].tclass.internal == tclass) {
			char *perm_name;

			for (j=0; (perm_name = selinux_catalog[i].av_perms[j].name); j++) {
				if (selinux_catalog[i].av_perms[j].internal == perm)
					return perm_name;
			}
			return "unknown";
		}
	}
	/* tclass is always same as external one, for kernel object classes */
	return security_av_perm_to_string(tclass, perm);
}

static void sepgsql_avc_reset(void)
{
	int i;

	MemoryContextReset(AvcMemCtx);

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);

	avc_version = selinux_state->version;
	avc_enforcing = selinux_state->enforcing;

	for (i=0; i < AVC_HASH_NUM_SLOTS; i++)
		avc_slot[i] = NIL;
	avc_datum_count = 0;

	LWLockRelease(SepgsqlAvcLock);
}

static void sepgsql_avc_reclaim(void)
{
	List *slot;
	ListCell *l;
	struct avc_datum *cache;

	while (avc_datum_count > AVC_HASH_NUM_NODES)
	{
		Assert(false);

		avc_lru_hint = (avc_lru_hint + 1) % AVC_HASH_NUM_SLOTS;
		slot = avc_slot[avc_lru_hint];
		foreach (l, slot)
		{
			cache = lfirst(l);

			if (cache->hot_cache)
			{
				cache->hot_cache = false;
				continue;
			}
			list_delete_ptr(slot, cache);
			pfree(cache);
			avc_datum_count--;
		}
	}
}

static void sepgsql_avc_compute(const security_context_t scon,
								const security_context_t tcon,
								security_class_t tclass,
								struct avc_datum *cache)
{
	security_class_t e_tclass;
	security_context_t svcon, tvcon, ncon;
	struct av_decision avd;

	svcon = (!security_check_context_raw(scon)
			 ? scon : sepgsqlGetUnlabeledContext());
	tvcon = (!security_check_context_raw(tcon)
			 ? tcon : sepgsqlGetUnlabeledContext());

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);

	e_tclass = trans_to_external_tclass(tclass);

	if (security_compute_av_raw(svcon, tvcon, e_tclass, 0, &avd))
		elog(ERROR, "SELinux: could not compute a new avc entry"
			 " scon=%s tcon=%s tclass=%u", svcon, tvcon, e_tclass);
	if (security_compute_create_raw(svcon, tvcon, e_tclass, &ncon))
		elog(ERROR, "SELinux: could not compute a new createcon "
			 "scon=%s tcon=%s tclass=%u", svcon, tvcon, e_tclass);

	cache->allowed = trans_to_internal_perms(e_tclass, avd.allowed);
	cache->decided = trans_to_internal_perms(e_tclass, avd.decided);
	cache->auditallow = trans_to_internal_perms(e_tclass, avd.auditallow);
	cache->auditdeny = trans_to_internal_perms(e_tclass, avd.auditdeny);
	cache->hot_cache = true;

	LWLockRelease(SepgsqlAvcLock);

	PG_TRY();
	{
		cache->scon = pstrdup(scon);
		cache->tcon = pstrdup(tcon);
		cache->ncon = pstrdup(ncon);
		cache->tclass = tclass;
	}
	PG_CATCH();
	{
		freecon(ncon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(ncon);
}

static struct avc_datum *sepgsql_avc_lookup(const security_context_t scon,
											const security_context_t tcon,
											security_class_t tclass)
{
	ListCell *l;
	struct avc_datum *cache;
	uint32 hash_key, index;
	MemoryContext oldctx;
	bool first = true;

	oldctx = MemoryContextSwitchTo(AvcMemCtx);

	hash_key = (DatumGetUInt32(hash_any((unsigned char *)scon, strlen(scon)))
				^ DatumGetUInt32(hash_any((unsigned char *)tcon, strlen(tcon)))
				^ (tclass << 2));
	index = hash_key % AVC_HASH_NUM_SLOTS;

	foreach (l, avc_slot[index])
	{
		cache = lfirst(l);

		if (cache->hash_key == hash_key
			&& cache->tclass == tclass
			&& !strcmp(cache->scon, scon)
			&& !strcmp(cache->tcon, tcon)) {
			/* move to the first of this slot */
			if (!first) {
				list_delete_ptr(avc_slot[index], cache);
				avc_slot[index] = lcons(cache, avc_slot[index]);
			}
			cache->hot_cache = true;
			goto out;
		}
		first = false;
	}
	/* reclaim avc, if needed */
	sepgsql_avc_reclaim();

	/* not found, and make a new one */
	cache = palloc0(sizeof(struct avc_datum));
	sepgsql_avc_compute(scon, tcon, tclass, cache);

	/* insert it */
	cache->hash_key = hash_key;
	avc_slot[index] = lcons(cache, avc_slot[index]);
	avc_datum_count++;

out:
	MemoryContextSwitchTo(oldctx);

	return cache;
}

static bool avc_audit_common(char *buffer, uint32 buflen,
							 const security_context_t scon,
							 const security_context_t tcon,
							 security_class_t tclass,
							 access_vector_t perms,
							 struct av_decision *avd,
							 const char *objname)
{
	access_vector_t denied, audited, mask;
	uint32 ofs = 0;

	denied = perms & ~avd->allowed;
	audited = denied ? (denied & avd->auditdeny) : (perms & avd->auditallow);
	if (!audited)
		return false;

	ofs += snprintf(buffer + ofs, buflen - ofs, "%s {",
					denied ? "denied" : "granted");
	for (mask = 1; mask; mask <<= 1)
	{
		if (audited & mask)
			ofs += snprintf(buffer + ofs, buflen - ofs, " %s",
                            sepgsql_av_perm_to_string(tclass, mask));
	}
	ofs += snprintf(buffer + ofs, buflen - ofs,
					" } scontext=%s tcontext=%s tclass=%s", scon, tcon,
					sepgsql_class_to_string(tclass));
	if (objname)
		ofs += snprintf(buffer + ofs, buflen - ofs,
						" name=%s", objname);

	return true;
}

static bool avc_permission_common(const security_context_t scon,
								  const security_context_t tcon,
								  security_class_t tclass,
								  access_vector_t perms,
								  struct av_decision *avd)
{
	access_vector_t denied;
	struct avc_datum *cache;

retry:
	cache = sepgsql_avc_lookup(scon, tcon, tclass);

	Assert(!!cache);

	if (avc_version != selinux_state->version) {
		/* security policy reloaded */
		sepgsql_avc_reset();
		goto retry;
	}

	if (avd)
	{
		memset(avd, 0, sizeof(struct av_decision));
		avd->allowed = cache->allowed;
		avd->decided = cache->decided;
		avd->auditallow = cache->auditallow;
		avd->auditdeny = cache->auditdeny;
	}

	denied = perms & ~cache->allowed;
	if (!perms || denied) {
		if (avc_enforcing)
			return false;

		/* grant permission to avoid flood of denied log
		 * on permissive mode*/
		cache->allowed |= perms;
	}
	return true;
}

void sepgsqlAvcPermission(const security_context_t scon,
						  const security_context_t tcon,
						  security_class_t tclass,
						  access_vector_t perms,
						  const char *objname)
{
	struct av_decision avd;
	char audit_buffer[2048];
	bool rc;

	rc = avc_permission_common(scon, tcon, tclass, perms, &avd);

	if (avc_audit_common(audit_buffer, sizeof(audit_buffer),
						 scon, tcon, tclass, perms, &avd, objname))
	{
		elog(rc ? NOTICE : ERROR, "SELinux: %s", audit_buffer);
	}
	else if (!rc)
		elog(ERROR, "SELinux: security policy violation");
}

bool sepgsqlAvcPermissionNoAbort(const security_context_t scon,
								 const security_context_t tcon,
								 security_class_t tclass,
								 access_vector_t perms,
								 const char *objname)
{
	struct av_decision avd;
	char audit_buffer[2048];
	bool rc;

	rc = avc_permission_common(scon, tcon, tclass, perms, &avd);

	if (avc_audit_common(audit_buffer, sizeof(audit_buffer),
						 scon, tcon, tclass, perms, &avd, objname))
		elog(NOTICE, "SELinux: %s", audit_buffer);

	return rc;
}

security_context_t sepgsqlAvcCreateCon(const security_context_t scon,
									   const security_context_t tcon,
									   security_class_t tclass)
{
	struct avc_datum *cache;

retry:
	cache = sepgsql_avc_lookup(scon, tcon, tclass);
	Assert(cache != NULL);

	if (avc_version != selinux_state->version) {
		/* security policy reloaded */
		sepgsql_avc_reset();
		goto retry;
	}

	return pstrdup(cache->ncon);
}

void sepgsqlAvcInit(void)
{
	bool found;

	/* local memory */
	AvcMemCtx = AllocSetContextCreate(TopMemoryContext,
									  "SE-PostgreSQL userspace avc",
									  ALLOCSET_DEFAULT_MINSIZE,
									  ALLOCSET_DEFAULT_INITSIZE,
									  ALLOCSET_DEFAULT_MAXSIZE);

	/* shared memory */
	selinux_state = ShmemInitStruct("SELinux policy state",
									sepgsqlShmemSize(), &found);
	if (!found)
	{
		int enforcing = security_getenforce();

		Assert(enforcing==0 || enforcing==1);

		LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
		selinux_state->version = 0;
		selinux_state->enforcing = enforcing;
		load_class_av_mapping();

		LWLockRelease(SepgsqlAvcLock);
	}

	/* reset local avc */
	sepgsql_avc_reset();
}

/*
 * SELinux state monitoring process
 */

static bool sepgsqlStateMonitorAlive = true;

static void sepgsqlStateMonitorSIGHUP(SIGNAL_ARGS)
{
	elog(NOTICE, "SELinux: userspace avc reset");
	sepgsql_avc_reset();
}

static int sepgsqlStateMonitorMain()
{
	char buffer[2048];
	struct sockaddr_nl addr;
	socklen_t addrlen;
	struct nlmsghdr *nlh;
	int rc, nl_sockfd;

	/* map shared memory segment */
	sepgsqlAvcInit();

	/* setup the signal handler */
	pqinitmask();
	pqsignal(SIGHUP, sepgsqlStateMonitorSIGHUP);
	pqsignal(SIGINT, SIG_IGN);
	pqsignal(SIGTERM, exit);
	pqsignal(SIGQUIT, exit);
	pqsignal(SIGUSR1, SIG_IGN);
	pqsignal(SIGUSR2, SIG_IGN);
	pqsignal(SIGCHLD, SIG_DFL);
	PG_SETMASK(&UnBlockSig);

	elog(LOG, "SELinux: policy state monitoring process (pid: %u)", getpid());

	/* open netlink socket */
	nl_sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_SELINUX);
	if (nl_sockfd < 0) {
		elog(NOTICE, "SELinux: could not open netlink socket");
		return 1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = SELNL_GRP_AVC;
	if (bind(nl_sockfd, (struct sockaddr *)&addr, sizeof(addr))) {
		elog(NOTICE, "SELinux: could not bint netlink socket");
		return 1;
	}

	/* waiting loop */
	while (sepgsqlStateMonitorAlive) {
		addrlen = sizeof(addr);
		rc = recvfrom(nl_sockfd, buffer, sizeof(buffer), 0,
					  (struct sockaddr *)&addr, &addrlen);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			elog(NOTICE, "SELinux: netlink recvfrom() errno=%d (%s)",
				 errno, strerror(errno));
			return 1;
		}

		if (addrlen != sizeof(addr)) {
			elog(NOTICE, "SELinux: netlink address truncated (len=%d)", addrlen);
			return 1;
		}

		if (addr.nl_pid) {
			elog(NOTICE, "SELinux: netlink received spoofed packet from: %u", addr.nl_pid);
			continue;
		}

		if (rc == 0) {
			elog(NOTICE, "SELinux: netlink received EOF on socket");
			return 1;
		}

		nlh = (struct nlmsghdr *) buffer;

		if (nlh->nlmsg_flags & MSG_TRUNC
			|| nlh->nlmsg_len > (unsigned int)rc) {
			elog(NOTICE, "SELinux: netlink incomplete netlink message");
			return 1;
		}
		switch (nlh->nlmsg_type) {
		case SELNL_MSG_SETENFORCE: {
			struct selnl_msg_setenforce *msg = NLMSG_DATA(nlh);

			elog(NOTICE, "SELinux: setenforce notifier (enforcing=%d)", msg->val);

			LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
			load_class_av_mapping();

			/* userspace avc invalidation */
			selinux_state->version = selinux_state->version + 1;
			selinux_state->enforcing = msg->val ? true : false;

			LWLockRelease(SepgsqlAvcLock);
			break;
		}
		case SELNL_MSG_POLICYLOAD: {
			struct selnl_msg_policyload *msg = NLMSG_DATA(nlh);

			elog(NOTICE, "SELinux: policyload notifier (seqno=%d)", msg->seqno);

			LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
			load_class_av_mapping();
			/* userspace avc invalidation */
			selinux_state->version = selinux_state->version + 1;

			LWLockRelease(SepgsqlAvcLock);
			break;
		}
		case NLMSG_ERROR: {
			struct nlmsgerr *err = NLMSG_DATA(nlh);
			if (err->error == 0)
				break;
			elog(NOTICE, "SELinux: netlink error message %d", -err->error);
			return 1;
		}
		default:
			elog(NOTICE, "SELinux: netlink unknown message type (%d)", nlh->nlmsg_type);
			return 1;
		}
	}
	return 0;
}

pid_t sepgsqlStartupWorkerProcess(void)
{
	pid_t chld;

	chld = fork();
	if (chld == 0)
	{
		ClosePostmasterPorts(false);

		on_exit_reset();

		exit(sepgsqlStateMonitorMain());
	}
	else if (chld > 0)
		return chld;

	return (pid_t) 0;
}
