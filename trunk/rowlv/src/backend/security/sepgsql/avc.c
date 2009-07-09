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
#include <signal.h>
#include <unistd.h>
#include <selinux/avc.h>

/*
 * AVC: userspace access vector cache
 *
 * SE-PostgreSQL asks in-kernel SELinux to make its decision whether
 * the required accesses should be allowed, or not, based on the unified 
 * security policy. It needs a system call invocation to communicate
 * a kernel feature, such as SELinux, but it is a heavy task in most cases
 * due to the context switching.
 *
 * The userspace avc enables to minimize the number of system call
 * invocations, using a chache mechanim for the certain pair of security
 * contexts and object classes (it means the kind of actions).
 * It enables to hold recently fetched results from the in-kernel SELinux,
 * and make a decision without context switching, if the cache hit.
 *
 * When the state of security policy is changed, the cached results
 * shall to be invalidated. The state monitoring process launched by
 * postmaster can receives the notification messages from the kernel
 * space, and invalidate the current version of avc.
 */
static MemoryContext AvcMemCtx;

#define AVC_HASH_NUM_SLOTS		256
#define AVC_HASH_NUM_NODES		180

typedef struct
{
	Oid		relid;
	Oid		secid;
} sepgsql_sid_t;

#define AVC_DATUM_NSID_SLOTS	19
typedef struct
{
	uint32				hash_key;

	security_class_t	tclass;
	sepgsql_sid_t		tsid;
	sepgsql_sid_t		nsid[AVC_DATUM_NSID_SLOTS];

	access_vector_t		allowed;
	access_vector_t		decided;
	access_vector_t		auditallow;
	access_vector_t		auditdeny;

	bool				hot_cache;
	bool				permissive;

	char				ncontext[1];
} avc_datum;

typedef struct avc_page
{
	struct avc_page *next;

	security_context_t	scontext;

	List *slot[AVC_HASH_NUM_SLOTS];

	uint32 avc_count;
	uint32 lru_hint;
} avc_page;

static avc_page *client_avc_page = NULL;

static int	avc_version;

static bool system_enforcing;

static int	local_enforcing = -1;

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

}	*selinux_state = NULL;

Size
sepgsqlShmemSize(void)
{
	if (!sepgsqlIsEnabled())
		return 0;

	return sizeof(*selinux_state);
}

/*
 * sepgsql_avc_check_valid
 *   returns false, if the given avc_page is already obsolete.
 */
static bool
sepgsql_avc_check_valid(void)
{
	bool result = true;

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	if (avc_version != selinux_state->version)
		result = false;
	LWLockRelease(SepgsqlAvcLock);

	return result;
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

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	avc_version = selinux_state->version;
	system_enforcing = selinux_state->enforcing;
	LWLockRelease(SepgsqlAvcLock);

	sepgsqlAvcSwitchClient();
}

/*
 * sepgsqlSetLocalEnforce
 *   It controls local enforcing/permissive mode.
 *   In the default, it follows system setting, but it can be set
 *   to permissive mode when the system internal stuff temporary
 *   want to disable access controls.
 *   (E.g, when temporary objects are cleaned up)
 *
 * local_enforcing < 0 (undefined, follows system setting)
 * local_enforcing = 0 (local permissive)
 * local_enforcing > 0 (local enforcing)
 */
int
sepgsqlSetLocalEnforce(int mode)
{
	int		old_enforcing = local_enforcing;

	local_enforcing = mode;

	return old_enforcing;
}

/*
 * sepgsqlGetEnforce
 *   It returns current enforcing/permissive mode
 */
bool
sepgsqlGetEnforce(void)
{
	if (!sepgsqlIsEnabled())
		return false;

	if (!sepgsql_avc_check_valid())
		sepgsql_avc_reset();

	if (local_enforcing < 0)
		return system_enforcing;
	else if (local_enforcing == 0)
		return false;
	else
		return true;
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
sepgsqlAvcAuditHook_t sepgsqlAvcAuditHook = NULL;

static void
avc_audit_common(security_context_t scontext,
				 security_context_t tcontext,
				 security_class_t tclass,
				 bool denied, access_vector_t audited,
				 const char *audit_name)
{
	StringInfoData	buf;
	access_vector_t mask;

	initStringInfo(&buf);
	appendStringInfo(&buf, "{");
	for (mask = 1; audited != 0; mask <<= 1)
	{
		if (audited & mask)
			appendStringInfo(&buf, " %s",
							 sepgsqlGetPermissionString(tclass, mask));
		audited &= ~mask;
	}
	appendStringInfo(&buf, " }");

	if (sepgsqlAvcAuditHook)
		(*sepgsqlAvcAuditHook)(scontext, tcontext,
							   sepgsqlGetClassString(tclass), buf.data,
							   denied, audit_name);
	else
	{
		appendStringInfo(&buf, " scontext=%s tcontext=%s tclass=%s",
						 scontext, tcontext,
						 sepgsqlGetClassString(tclass));
		if (audit_name)
			appendStringInfo(&buf, " name=%s", audit_name);

		ereport(LOG,
				(errcode(ERRCODE_SELINUX_AUDIT),
				 errmsg("SELinux: %s %s",
						denied ? "denied" : "granted", buf.data)));
	}
}

/*
 * avc_make_entry
 *   makes a query to in-kernel SELinux and an avc_datum object to
 *   cache the result of SELinux's decision for access rights and
 *   default security context.
 */
#define avc_hash_key(trelid,tsecid,tclass)			\
	(hash_uint32((trelid) ^ (tsecid) ^ ((tclass) << 3)))

static avc_datum *
avc_make_entry(avc_page *page, Oid relid, Oid secid, security_class_t tclass)
{
	security_context_t	scontext, tcontext, ncontext;
	security_class_t	tclass_ex;
	MemoryContext		oldctx;
	struct av_decision	avd;
	avc_datum		   *cache;
	uint32				hash_key, index;

	hash_key = avc_hash_key(relid, secid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	scontext = page->scontext;
	tcontext = securityRawSecLabelOut(relid, secid);

	/*
	 * Compute SELinux permission
	 */
	tclass_ex = sepgsqlTransToExternalClass(tclass);
	if (tclass_ex > 0)
	{
		if (security_compute_av_flags_raw(scontext, tcontext,
										  tclass_ex, 0, &avd) < 0)
			ereport(ERROR,
					(errcode(ERRCODE_SELINUX_ERROR),
					 errmsg("SELinux: unable to compute av_decision: "
							"scontext=%s tcontext=%s tclass=%s",
							scontext, tcontext,
							sepgsqlGetClassString(tclass))));
		sepgsqlTransToInternalPerms(tclass, &avd);
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

	/*
	 * Compute New security context
	 */
	if (security_compute_create_raw(scontext, tcontext,
									tclass_ex, &ncontext) < 0)
	{
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: unable to compute new context: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsqlGetClassString(tclass))));
	}

	/*
	 * Copy them to avc_datum
	 */
	oldctx = MemoryContextSwitchTo(AvcMemCtx);
	PG_TRY();
	{
		cache = palloc0(sizeof(avc_datum) + strlen(ncontext));
	}
	PG_CATCH();
	{
		freecon(ncontext);
		PG_RE_THROW();
	}
	PG_END_TRY();

	cache->hash_key = hash_key;
	cache->tclass = tclass;
	cache->tsid.relid = relid;
	cache->tsid.secid = secid;
	/* cache->nsid shall be set later */

	cache->allowed = avd.allowed;
	cache->decided = avd.decided;
	cache->auditallow = avd.auditallow;
	cache->auditdeny = avd.auditdeny;

	cache->hot_cache = true;
	if (avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE)
		cache->permissive = true;
	strcpy(cache->ncontext, ncontext);
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
avc_lookup(avc_page *page, Oid trelid, Oid tsecid,
		   security_class_t tclass)
{
	avc_datum *cache = NULL;
	uint32 hash_key, index;
	ListCell *l;

	/* check avc invalidation */
	if (!sepgsql_avc_check_valid())
		sepgsql_avc_reset();

	/* lookup avc entry */
	hash_key = avc_hash_key(trelid, tsecid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	foreach (l, page->slot[index])
	{
		cache = lfirst(l);
		if (cache->hash_key == hash_key
			&& cache->tclass == tclass
			&& cache->tsid.relid == trelid
			&& cache->tsid.secid == tsecid)
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
	client_avc_page = sepgsqlAvcSwitch(client_avc_page,
									   sepgsqlGetClientLabel());
}

/*
 * sepgsqlClientHasPerms
 *   checks client's privileges on given objects via uAVC.
 */
bool
sepgsqlClientHasPermsSid(Oid relid, Oid secid,
						 security_class_t tclass,
						 access_vector_t required,
						 const char *audit_name, bool abort)
{
	security_context_t	scontext, tcontext;
	access_vector_t		denied, audited;
	avc_datum		   *cache;
	bool				result = true;

	Assert(required != 0);

retry:
	cache = avc_lookup(client_avc_page, relid, secid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page, relid, secid, tclass);
	if (!sepgsql_avc_check_valid())
		goto retry;

	denied = required & ~cache->allowed;
	audited = denied ? (denied & cache->auditdeny)
					 : (required & cache->auditallow);
	if (audited)
	{
		scontext = sepgsqlTransSecLabelOut(client_avc_page->scontext);
		tcontext = securityTransSecLabelOut(relid, secid);
		avc_audit_common(scontext, tcontext, cache->tclass,
						 !!denied, audited, audit_name);
	}

	if (denied)
	{
		if (!sepgsqlGetEnforce() || cache->permissive)
			cache->allowed |= required;		/* prevent flood of audit log */
		else
			result = false;
	}

	if (abort && !result)
	{
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: security policy violation")));
	}

	return result;
}

bool
sepgsqlClientHasPermsTup(Oid relid, HeapTuple tuple,
						 security_class_t tclass,
						 access_vector_t required, bool abort)
{
	Oid			secid = HeapTupleGetSecLabel(tuple);
	const char *audit_name = sepgsqlAuditName(relid, tuple);

	return sepgsqlClientHasPermsSid(relid, secid, tclass, required,
									audit_name, abort);
}

/*
 * sepgsqlClientCreateSecid
 * sepgsqlClientCreateLabel
 */
Oid
sepgsqlClientCreateSecid(Oid trelid, Oid tsecid,
						 security_class_t tclass, Oid nrelid)
{
	avc_datum  *cache;
	int			index;
	Oid			nsecid;

retry:
	cache = avc_lookup(client_avc_page, trelid, tsecid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page,
							   trelid, tsecid, tclass);

	index = (nrelid % AVC_DATUM_NSID_SLOTS);
	if (cache->nsid[index].relid != nrelid)
	{
		cache->nsid[index].secid
			= securityRawSecLabelIn(nrelid, cache->ncontext);
		cache->nsid[index].relid = nrelid;
	}
	nsecid = cache->nsid[index].secid;

	if (!sepgsql_avc_check_valid())
		goto retry;

	return nsecid;
}

security_context_t
sepgsqlClientCreateLabel(Oid trelid, Oid tsecid,
						 security_class_t tclass)
{
	avc_datum  *cache;

retry:
	cache = avc_lookup(client_avc_page,
					   trelid, tsecid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page,
							   trelid, tsecid, tclass);
	if (!sepgsql_avc_check_valid())
		goto retry;

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

	Assert(required != 0);

	tclass_ex = sepgsqlTransToExternalClass(tclass);
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
		sepgsqlTransToInternalPerms(tclass, &avd);
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

security_context_t
sepgsqlComputeCreate(security_context_t scontext,
					 security_context_t tcontext,
					 security_class_t tclass)
{
	security_context_t ncontext, result;
	security_class_t tclass_ex;

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

	ereport(LOG, 
			(errcode(ERRCODE_SELINUX_INFO),
			 errmsg("%s", buffer)));

	return 0;
}

static int
sepgsql_cb_setenforce(int enforce)
{
	/* switch enforcing/permissive */
	LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
	selinux_state->version = selinux_state->version + 1;
	selinux_state->enforcing = (enforce ? true : false);
	LWLockRelease(SepgsqlAvcLock);

	return 0;
}

static int
sepgsql_cb_policyload(int seqno)
{
	/* invalidate local avc */
	LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
	selinux_state->version = selinux_state->version + 1;
	LWLockRelease(SepgsqlAvcLock);

	return 0;
}

static int
sepgsqlWorkerMain(void)
{
	union selinux_callback cb;

	ClosePostmasterPorts(false);

	on_exit_reset();

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

	ereport(LOG,
			(errcode(ERRCODE_SELINUX_INFO),
			 errmsg("SELinux: security policy monitor (pid=%u)", getpid())));
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
		exit(sepgsqlWorkerMain());
	else if (chld > 0)
		return chld;

	return (pid_t) 0;
}
