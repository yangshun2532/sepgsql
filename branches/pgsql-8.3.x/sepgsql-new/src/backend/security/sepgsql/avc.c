/*
 * src/backend/security/sepgsql/avc.c
 *	  SE-PostgreSQL userspace access vector cache
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/hash.h"
#include "catalog/pg_security.h"
#include "libpq/pqsignal.h"
#include "postmaster/postmaster.h"
#include "security/sepgsql.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "utils/memutils.h"
#include "utils/syscache.h"
#include <linux/netlink.h>
#include <linux/selinux_netlink.h>
#include <signal.h>
#include <unistd.h>

/*
 * AVC: userspace Access Vector Cache
 *
 * SE-PostgreSQL makes inqueries for SELinux to check whether the security
 * policy allows the required action, or not. However, it need to invoke
 * system call because SELinux is a kernel feature and it hold its security
 * policy in the kernel memory.
 *
 * AVC enables to reduce the number of kernel invocation, with caching
 * the result of inquiries. When we have to make a decision based on the
 * security policy of SELinux, it tries to find up an appropriate cache
 * entry on the uAVC. If exist, we don't need to invoke a system call
 * and can reduce unnecessary overhead.
 *
 * If not exist, SE-PostgreSQL makes a new cache entry based on the
 * result of inquiries, and chains it on uAVC to prepare the following
 * decision makings.
 *
 * uAVC has a version number to check whether it is now valid, or not.
 * Not need to say, uAVC cache entry has to be invalid just after
 * policy reloaded or state change.
 * If it is not match the latest one, updated by the policy state
 * monitoring process, uAVC has to be reseted.
 */
static MemoryContext AvcMemCtx;

#define AVC_HASH_NUM_SLOTS		256
#define AVC_HASH_NUM_NODES		180

typedef struct
{
	uint32				hash_key;

	security_class_t	tclass;
	sepgsql_sid_t		tsid;
	sepgsql_sid_t		nsid;
	security_context_t	ncontext;

	access_vector_t		allowed;
	access_vector_t		decided;
	access_vector_t		auditallow;
	access_vector_t		auditdeny;

	bool				hot_cache;
} avc_datum;

typedef struct avc_page
{
	struct avc_page *next;

	int		avc_version;	/* copied from global state */

	bool	avc_enforcing;	/* copied from global state */

	security_context_t	scontext;

	List *slot[AVC_HASH_NUM_SLOTS];

	uint32 avc_count;
	uint32 lru_hint;
} avc_page;

static avc_page *client_avc_page = NULL;

/*
 * selinux_state
 *
 * This structure shows the global state of SELinux and its security
 * policy, and it is assigned on shared memory region.
 *
 * The selinux_state->version should be checked prior to any avc
 * accesses. If avc_page->avc_version is not matched with the
 * global state, it means security policy is reloaded, system booleans
 * are changed, or working mode (enforcing/permissive) is changed.
 * The selinux_state->enforcing means current working mode. If it it
 * true, it works in enforcing mode, elsewhere permissive mode.
 *
 * The only process able to update these variable are policy state
 * monitoring process forked by postmaster. It enables to receive
 * notifications from the kernwl via netlink socket.
 *
 * These global state is protected by SepgsqlAvcLock LWlock, so
 * we need to acquire this lock when it is refered.
 */
struct
{
	int			version;

	bool		enforcing;

}	*selinux_state = NULL;

Size
sepgsqlShmemSize(void)
{
	if (!sepgsqlIsEnabled())
		return 0;

	return sizeof(*selinux_state);
}

/*
 * sepgsql_avc_reset
 *   clears all AVC entries and update its version.
 *   caller need to hold SepgsqlAvcLock
 */
static void
sepgsql_avc_reset(void)
{
	MemoryContextReset(AvcMemCtx);

	client_avc_page = NULL;

	sepgsqlAvcSwitchClient();
}

/*
 * sepgsql_avc_reclaim
 *   reclaims recently unused AVC entries, when the number of
 *   caches overs AVC_HASH_NUM_NODES.
 */
static void
sepgsql_avc_reclaim(avc_page *page)
{
	ListCell *l;
	avc_datum *cache;

	while (page->avc_count > AVC_HASH_NUM_NODES)
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
 * avc_audit_common
 *   generates an audit message on the give string buffer based on
 *   the given av_decision which means the resutl of permission checks.
 */
static void
avc_audit_common(char *buffer, uint32 buflen,
				 security_context_t scontext,
				 security_context_t tcontext,
				 security_class_t tclass,
				 access_vector_t audited,
				 bool denied,
				 const char *audit_name)
{
	access_vector_t mask;
	uint32 ofs = 0;

	ofs += snprintf(buffer + ofs, buflen - ofs, "%s {",
					denied ? "denied" : "granted");
	for (mask = 1; audited != 0; mask <<= 1)
	{
		if (audited & mask)
			ofs += snprintf(buffer + ofs, buflen - ofs, " %s",
							sepgsqlGetPermissionString(tclass, mask));
		audited &= ~mask;
	}
	ofs += snprintf(buffer + ofs, buflen - ofs, " } ");

	ofs += snprintf(buffer + ofs, buflen - ofs,
					"scontext=%s tcontext=%s tclass=%s",
					scontext, tcontext,
					sepgsqlGetClassString(tclass));

	if (audit_name)
		ofs += snprintf(buffer + ofs, buflen - ofs, " name=%s", audit_name);
}

/*
 * avc_make_entry
 *   makes a query to in-kernel SELinux and an avc_datum object to
 *   cache the result of SELinux's decision for access rights and
 *   default security context.
 */
#define avc_hash_key(tcontext, tclass)		((tsid) ^ ((tclass) << 3))

static avc_datum *
avc_make_entry(avc_page *page, sepgsql_sid_t tsid, security_class_t tclass)
{
	security_context_t scontext, tcontext, ncontext;
	security_class_t tclass_ex;
	MemoryContext oldctx;
	struct av_decision avd;
	avc_datum *cache;
	uint32 hash_key, index;

	hash_key = avc_hash_key(tsid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	oldctx = MemoryContextSwitchTo(AvcMemCtx);
	cache = palloc0(sizeof(avc_datum));
	cache->hash_key = hash_key;
	cache->tsid = tsid;
	cache->tclass = tclass;

	scontext = page->scontext;
	tcontext = securityLookupSecurityLabel(tsid);
	if (!tcontext || !sepgsqlCheckValidSecurityLabel(tcontext))
		tcontext = sepgsqlGetUnlabeledLabel();

	tclass_ex = sepgsqlTransToExternalClass(tclass);

	if (security_compute_av_raw(scontext, tcontext, tclass_ex, 0, &avd) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute av_decision: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsqlGetClassString(tclass))));
	sepgsqlTransToInternalPerms(tclass, &avd);

	cache->allowed = avd.allowed;
	cache->decided = avd.decided;
	cache->auditallow = avd.auditallow;
	cache->auditdeny = avd.auditdeny;
	cache->hot_cache = true;

	if (security_compute_create_raw(scontext, tcontext, tclass_ex, &ncontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute new context: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsqlGetClassString(tclass))));

	PG_TRY();
	{
		cache->ncontext = pstrdup(ncontext);
	}
	PG_CATCH();
	{
		freecon(ncontext);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(ncontext);

	sepgsql_avc_reclaim(page);

	page->slot[index] = lcons(cache, page->slot[index]);

	page->avc_count++;

	MemoryContextSwitchTo(oldctx);

	return cache;
}

/*
 * avc_lookup
 *   It lookups required avc entry. Because it also checks avc_version
 *   on the global state, the caller has to hold SepgsqlAvcLock.
 */
static avc_datum *
avc_lookup(avc_page *page, sepgsql_sid_t tsid, security_class_t tclass)
{
	avc_datum *cache = NULL;
	uint32 hash_key, index;
	ListCell *l;

	/* check avc invalidation */
	if (page->avc_version != selinux_state->version)
		sepgsql_avc_reset();

	/* lookup avc entry */
	hash_key = avc_hash_key(tsid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	foreach (l, page->slot[index])
	{
		cache = lfirst(l);
		if (cache->hash_key == hash_key
			&& cache->tclass == tclass
			&& cache->tsid == tsid)
		{
			cache->hot_cache = true;
			return cache;
		}
	}
	return NULL;
}

/*
 * sepgsqlAvcSwitchClientLabel()
 *   switches current avc_page.
 *
 * NOTE: In most cases, SE-PostgreSQL checks whether client is allowed
 * to do required actions (like SELECT, UPDATE, ...) on the targets.
 * Both of client and targets have its security context, and all rules
 * are described as relationship between security context of a client,
 * a target and kind of actions.
 * However, the security context of client is unchanged in SE-PostgreSQL
 * (an exception is invocation of trusted procedure), so we can omit
 * to compare security context of client with entries of uAVC.
 * The avc_page is a set of avc_datum sorted out by the security context
 * of client, so we can lookup correct avc_datum on currently focued
 * avc_page without comparing the security context of client.
 * The reason why we don't not use a unique uAVC is the security context
 * of client does not have its security identifier on pg_security, so
 * it requires strcmp() for each entries, but it is heavier than integer
 * comparisons.
 * Thus we have to switch current avc_page, whenever the security context
 * of client changes (via trusted procedure). It makes performance well
 * in most cases.
 */
static avc_page *
sepgsqlAvcSwitch(avc_page *old_page, security_context_t scontext)
{
	MemoryContext oldctx;
	avc_page *new_page;
	int i;

	if (old_page)
	{
		new_page = old_page;
		do {
			if (strcmp(new_page->scontext, scontext) == 0)
				return new_page;

			new_page = old_page->next;
		} while (new_page != old_page);
	}

	/* Not found, so create a new avc_page */
	oldctx = MemoryContextSwitchTo(AvcMemCtx);
	new_page = palloc0(sizeof(avc_page));
	new_page->scontext = pstrdup(scontext);
	MemoryContextSwitchTo(oldctx);

	for (i=0; i < AVC_HASH_NUM_SLOTS; i++)
		new_page->slot[i] = NIL;

	/* copy the global state of SELinux */
	new_page->avc_version = selinux_state->version;
	new_page->avc_enforcing = selinux_state->enforcing;

	if (!old_page)
	{
		new_page->next = new_page;
	}
	else
	{
		new_page->next = old_page->next;
		old_page->next = new_page;
	}

	return new_page;
}

void
sepgsqlAvcSwitchClient(void)
{
	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	client_avc_page = sepgsqlAvcSwitch(client_avc_page,
									   sepgsqlGetClientLabel());
	LWLockRelease(SepgsqlAvcLock);
}

/*
 * sepgsqlClientHasPerms
 *   checks client's privileges on given objects via uAVC.
 */
bool
sepgsqlClientHasPerms(sepgsql_sid_t tsid,
					  security_class_t tclass,
					  access_vector_t required,
					  const char *audit_name, bool abort)
{
	char audit_buffer[2048];
	access_vector_t denied, audited;
	avc_datum *cache;
	bool rc = true;

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	cache = avc_lookup(client_avc_page, tsid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page, tsid, tclass);
	LWLockRelease(SepgsqlAvcLock);

	denied = required & ~cache->allowed;
	audited = denied ? (denied & cache->auditdeny)
					 : (required & cache->auditallow);
	if (audited)
	{
		security_context_t scon, tcon;

		scon = sepgsqlSecurityLabelTransOut(client_avc_page->scontext);
		tcon = securityTransSecLabelOut(tsid);

		avc_audit_common(audit_buffer, sizeof(audit_buffer),
						 scon, tcon, cache->tclass,
						 audited, !!denied, audit_name);
		pfree(scon);
		pfree(tcon);
	}

	if (!required || denied)
	{
		if (client_avc_page->avc_enforcing)
			rc = false;
		else
			cache->allowed |= required;		/* prevent flood of audit log */
	}

	if (audited)
		ereport((!rc && abort) ? ERROR : NOTICE,
				(errcode(ERRCODE_SELINUX_AUDIT),
				 errmsg("SELinux: %s", audit_buffer)));
	else if (!rc && abort)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_AUDIT),
				 errmsg("SELinux: security policy violation")));

	return rc;
}

/*
 * sepgsqlClientCreate
 * sepgsqlClientCreateLabel
 *   It returns security label of database object newly created.
 *   sepgsqlClientCreate() returns it as sepgsql_sid_t, and
 *   sepgsqlClientCreateLabel() returns it as security_context_t.
 *   Please note that these types are not different in this version,
 *   but sepgsql_sid_t is planned to replace by an identifier.
 */
sepgsql_sid_t
sepgsqlClientCreate(sepgsql_sid_t tsid, security_class_t tclass)
{
	avc_datum *cache;

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	cache = avc_lookup(client_avc_page, tsid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page, tsid, tclass);
	LWLockRelease(SepgsqlAvcLock);

	if (!OidIsValid(cache->nsid))
		cache->nsid = securityLookupSecurityId(cache->ncontext);

	return cache->nsid;
}

security_context_t
sepgsqlClientCreateLabel(sepgsql_sid_t tsid, security_class_t tclass)
{
	avc_datum *cache;

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	cache = avc_lookup(client_avc_page, tsid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page, tsid, tclass);
	LWLockRelease(SepgsqlAvcLock);

	return cache->ncontext;
}

/*
 * sepgsql_shmem_init
 *   attaches shared memory segment.
 */
static void
sepgsql_shmem_init(void)
{
	bool found;

	selinux_state = ShmemInitStruct("SELinux policy state",
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
 * sepgsqlAvcInit
 *   initialize local uAVC facility.
 */
void
sepgsqlAvcInit(void)
{
	/*
	 * local memory context
	 */
	AvcMemCtx = AllocSetContextCreate(TopMemoryContext,
									  "SE-PostgreSQL userspace avc",
									  ALLOCSET_DEFAULT_MINSIZE,
									  ALLOCSET_DEFAULT_INITSIZE,
									  ALLOCSET_DEFAULT_MAXSIZE);
	sepgsql_shmem_init();

	/*
	 * reset local avc
	 */
	sepgsql_avc_reset();
}

/*
 * sepgsqlComputePerms
 * sepgsqlComputeCreate
 *
 * The following two functions make a query to in-kernel SELinux
 * without userspace caches, due to some reasons.
 * The AVC can cover most of cases, but some of corner cases are
 * not suitable for AVC structure, so we need uncached interfaces.
 * For example, AVC is unavailable when we tries to load a shared
 * library module, because security context of the library does not
 * have its security identifier, so we cannot put it on AVC.
 */
bool
sepgsqlComputePerms(security_context_t scontext,
					security_context_t tcontext,
					security_class_t tclass,
					access_vector_t required,
					const char *audit_name, bool abort)
{
	access_vector_t denied, audited;
	security_class_t tclass_ex;
	struct av_decision avd;
	char audit_buffer[2048];
	bool rc = true;

	scontext = (!security_check_context_raw(scontext)
				? scontext : sepgsqlGetUnlabeledLabel());
	tcontext = (!security_check_context_raw(tcontext)
				? tcontext : sepgsqlGetUnlabeledLabel());

	tclass_ex = sepgsqlTransToExternalClass(tclass);
	if (security_compute_av_raw(scontext, tcontext, tclass_ex, 0, &avd) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute an av_decision"
						" scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsqlGetClassString(tclass))));
	sepgsqlTransToInternalPerms(tclass, &avd);

	denied = required & ~avd.allowed;
	audited = denied ? (denied & avd.auditdeny) : (required & avd.auditallow);
	if (audited)
	{
		security_context_t scon, tcon;

		scon = sepgsqlSecurityLabelTransOut(scontext);
		tcon = sepgsqlSecurityLabelTransOut(tcontext);

		avc_audit_common(audit_buffer, sizeof(audit_buffer),
						 scon, tcon, tclass,
						 audited, !!denied, audit_name);
	}

	if (!required || denied)
	{
		if (security_getenforce() > 0)
			rc = false;
	}

	if (audited)
		ereport((!rc && abort) ? ERROR : NOTICE,
				(errcode(ERRCODE_SELINUX_AUDIT),
				 errmsg("SELinux: %s", audit_buffer)));
	else if (!rc && abort)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_AUDIT),
				 errmsg("SELinux: security policy violation")));

	return rc;
}

security_context_t
sepgsqlComputeCreate(security_context_t scontext,
					 security_context_t tcontext,
					 security_class_t tclass)
{
	security_context_t ncontext, result;
	security_class_t tclass_ex;

	scontext = (!security_check_context_raw(scontext)
				? scontext : sepgsqlGetUnlabeledLabel());
	tcontext = (!security_check_context_raw(tcontext)
				? tcontext : sepgsqlGetUnlabeledLabel());

	tclass_ex = sepgsqlTransToExternalClass(tclass);
	if (security_compute_create_raw(scontext, tcontext, tclass_ex, &ncontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute a default context"
						" scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsqlGetClassString(tclass))));
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
 * SELinux state monitoring process
 *
 * This process is forked from postmaster to monitor the state of SELinux.
 * SELinux can make a notifier message to userspace object manager via
 * netlink socket. When it receives the message, it updates selinux_state
 * structure assigned on shared memory region to make any instance reset
 * its AVC soon.
 */
static int
sepgsqlStateMonitorMain()
{
	char		buffer[2048];
	struct sockaddr_nl addr;
	socklen_t	addrlen;
	struct nlmsghdr *nlh;
	int			rc, nl_sockfd;

	/*
	 * map shared memory segment
	 */
	sepgsql_shmem_init();

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

	ereport(NOTICE,
			(errcode(ERRCODE_SELINUX_INFO),
			 errmsg("SELinux: policy state monitor process (pid: %u)",
					getpid())));
	/*
	 * open netlink socket
	 */
	nl_sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_SELINUX);
	if (nl_sockfd < 0)
	{
		ereport(NOTICE,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not open netlink socket")));
		return 1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = SELNL_GRP_AVC;
	if (bind(nl_sockfd, (struct sockaddr *) &addr, sizeof(addr)))
	{
		ereport(NOTICE,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not bind netlink socket")));
		return 1;
	}

	/*
	 * waiting loop
	 */
	while (true)
	{
		addrlen = sizeof(addr);
		rc = recvfrom(nl_sockfd, buffer, sizeof(buffer), 0,
					  (struct sockaddr *) &addr, &addrlen);
		if (rc < 0)
		{
			if (errno == EINTR)
				continue;

			ereport(NOTICE,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: error on netlink recvfrom(): %s",
							strerror(errno))));
			return 1;
		}

		if (addrlen != sizeof(addr))
		{
			ereport(NOTICE,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: netlink address truncated (len=%d)",
							addrlen)));
			return 1;
		}

		if (addr.nl_pid)
		{
			ereport(NOTICE,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: netlink received spoofed packet from: %u",
							addr.nl_pid)));
			continue;
		}

		if (rc == 0)
		{
			ereport(NOTICE,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: netlink received EOF")));
			return 1;
		}

		nlh = (struct nlmsghdr *) buffer;
		if (nlh->nlmsg_flags & MSG_TRUNC || nlh->nlmsg_len > (unsigned int) rc)
		{
			ereport(NOTICE,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: netlink incomplete message")));
			return 1;
		}

		switch (nlh->nlmsg_type)
		{
			case SELNL_MSG_SETENFORCE:
				{
					struct selnl_msg_setenforce *msg = NLMSG_DATA(nlh);

					ereport(NOTICE,
							(errcode(ERRCODE_SELINUX_INFO),
							 errmsg("SELinux: setenforce notifier"
									" (enforcing=%d)", msg->val)));
					/* switch enforcing/permissive */
					LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
					selinux_state->version = selinux_state->version + 1;
					selinux_state->enforcing = msg->val ? true : false;
					LWLockRelease(SepgsqlAvcLock);
					break;
				}
			case SELNL_MSG_POLICYLOAD:
				{
					struct selnl_msg_policyload *msg = NLMSG_DATA(nlh);

					ereport(NOTICE,
							(errcode(ERRCODE_SELINUX_INFO),
							 errmsg("policyload notifier (seqno=%d)",
									msg->seqno)));

					/* security policy reloaded */
					LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
					selinux_state->version = selinux_state->version + 1;
					LWLockRelease(SepgsqlAvcLock);
					break;
				}
			case NLMSG_ERROR:
				{
					struct nlmsgerr *err = NLMSG_DATA(nlh);

					if (err->error == 0)
						break;

					ereport(NOTICE,
							(errcode(ERRCODE_SELINUX_ERROR),
							 errmsg("SELinux: netlink error: %s",
									strerror(-err->error))));
					return 1;
				}
			default:
				ereport(NOTICE,
						(errcode(ERRCODE_SELINUX_ERROR),
						 errmsg("netlink unknown message type (%d)",
								nlh->nlmsg_type)));
				return 1;
		}
	}
	return 0;
}

pid_t
sepgsqlStartupWorkerProcess(void)
{
	pid_t		chld;

	if (!sepgsqlIsEnabled())
		return (pid_t) 0;

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
