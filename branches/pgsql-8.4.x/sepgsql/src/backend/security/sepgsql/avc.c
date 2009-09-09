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
#include "miscadmin.h"
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

static avc_page *current_page = NULL;

static int avc_version;

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
 * sepgsql_shmem_init
 *   attaches shared memory segment.
 */
static void
sepgsqlShmemInit(void)
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
 * sepgsqlAvcReset
 *
 * It invalidate access vector cache. It has to be called on errors,
 * because avc entries for newly created context is uncertain whether
 * it is still valid, or not.
 */
void
sepgsqlAvcReset(void)
{
	if (!sepgsqlIsEnabled())
		return;

	MemoryContextReset(AvcMemCtx);

	current_page = NULL;

	sepgsqlAvcSwitchClient(sepgsqlGetClientLabel());
}

/*
 * sepgsqlAvcCheckValid
 *
 * It checks whether the current AVC pages are valid, or not.
 * If state monitoring process already received an invalidation
 * message from the kernel, it clears current AVC pages and
 * returns false.
 */
static bool
sepgsqlAvcCheckValid(void)
{
	bool result = true;

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	if (avc_version != selinux_state->version)
	{
		/* reset invalid avc pages, and makes an empty one */
		MemoryContextReset(AvcMemCtx);

		current_page = NULL;

		sepgsqlAvcSwitchClient(sepgsqlGetClientLabel());

		/* copy current version to local */
		avc_version = selinux_state->version;

		result = false;
	}
	LWLockRelease(SepgsqlAvcLock);

	return result;
}

/*
 * sepgsqlAvcInitialize
 *
 * It allocates a memory context for userspace AVC,
 * map shared memory segment, and initialize avc_page
 * for the current client's privilege.
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
	 * local memory context
	 */
	AvcMemCtx = AllocSetContextCreate(TopMemoryContext,
									  "SE-PostgreSQL userspace avc",
									  ALLOCSET_DEFAULT_MINSIZE,
									  ALLOCSET_DEFAULT_INITSIZE,
									  ALLOCSET_DEFAULT_MAXSIZE);
	sepgsqlShmemInit();

	/*
	 * Switch to local permissive mode
	 */
	if (!MyProcPort)
		sepgsqlSetEnforce(0);

	/*
	 * selinux_state->version is never negative value,
	 * so this call always reset local avc.
	 */
	avc_version = -1;
	sepgsqlAvcCheckValid();
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
static int  local_enforce = -1; /* undefined */

bool
sepgsqlGetEnforce(void)
{
	bool	rc;

	if (local_enforce < 0)
	{
		LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
		rc = selinux_state->enforcing;
		LWLockRelease(SepgsqlAvcLock);

		return rc;
	}

	return (local_enforce > 0 ? true : false);
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
 * sepgsqlAvcReclaim
 *
 * It wipes recently unused AVC entries, when the number of entries
 * reaches AVC_HASH_NUM_NODES..
 */
static void
sepgsqlAvcReclaim(avc_page *page)
{
	ListCell	   *l;
	avc_datum	   *cache;

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
 * sepgsqlAvcMakeEntry
 *
 * It makes a new AVC entry and insert it on the avc_page.
 * If is hold more than AVC_HASH_NUM_NODES entries, recently unused
 * avc_datum shall be reclaimed.
 */
#define avc_hash_key(trelid,tsecid,tclass)			\
	(hash_uint32((trelid) ^ (tsecid) ^ ((tclass) << 3)))

static avc_datum *
sepgsqlAvcMakeEntry(avc_page *page, sepgsql_sid_t tsid, uint16 tclass)
{
	security_context_t	scontext, tcontext, ncontext;
	security_class_t	tclass_ex;
	MemoryContext		oldctx;
	struct av_decision	avd;
	avc_datum		   *cache;
	uint32				hash_key, index;

	hash_key = avc_hash_key(tsid.relid, tsid.secid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	scontext = page->scontext;
	tcontext = securityRawSecLabelOut(tsid.relid, tsid.secid);

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
	cache->tsid.relid = tsid.relid;
	cache->tsid.secid = tsid.secid;
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

	sepgsqlAvcReclaim(page);

	page->slot[index] = lcons(cache, page->slot[index]);
	page->avc_count++;

	MemoryContextSwitchTo(oldctx);

	return cache;
}

/*
 * sepgsqlAvcLookup
 *
 * It lookups required AVC entry.
 */
static avc_datum *
sepgsqlAvcLookup(avc_page *page, sepgsql_sid_t tsid, uint16 tclass)
{
	avc_datum  *cache = NULL;
	uint32		hash_key, index;
	ListCell   *l;

	hash_key = avc_hash_key(tsid.relid, tsid.secid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	foreach (l, page->slot[index])
	{
		cache = lfirst(l);
		if (cache->hash_key == hash_key
			&& cache->tclass == tclass
			&& cache->tsid.relid == tsid.relid
			&& cache->tsid.secid == tsid.secid)
		{
			cache->hot_cache = true;
			return cache;
		}
	}
	return NULL;
}

/*
 * sepgsqlAvcSwitchClientLabel()
 *
 * It switches the current avc_page.
 * An avc_page is a set of cached access control decisions associated
 * with a certain privilege of the client. This structure enables to
 * lookup required avc_datum without any comparison to the subject
 * label.
 */
void
sepgsqlAvcSwitchClient(const char *scontext)
{
	MemoryContext	oldctx;
	avc_page	   *new_page;
	int				i;

	if (current_page)
	{
		new_page = current_page;
		do {
			if (strcmp(new_page->scontext, scontext) == 0)
			{
				current_page = new_page;
				return;
			}
			new_page = new_page->next;
		} while (new_page != current_page);
	}

	/* Not found, create a new avc_page */
	oldctx = MemoryContextSwitchTo(AvcMemCtx);
	new_page = palloc0(sizeof(avc_page));
	new_page->scontext = pstrdup(scontext);
	MemoryContextSwitchTo(oldctx);

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
	avc_datum	   *cache;
	uint32			denied, audited;
	bool			result = true;

	Assert(required != 0);

	do {
		cache = sepgsqlAvcLookup(current_page, tsid, tclass);
		if (!cache)
			cache = sepgsqlAvcMakeEntry(current_page, tsid, tclass);
	} while (!sepgsqlAvcCheckValid());

	denied = required & ~cache->allowed;
	audited = denied ? (denied & cache->auditdeny)
					 : (required & cache->auditallow);
	if (audited)
	{
		sepgsqlAvcAudit(!!denied,
						current_page->scontext,
						securityRawSecLabelOut(tsid.relid, tsid.secid),
						cache->tclass, audited, audit_name);
	}

	if (denied)
	{
		if (!sepgsqlGetEnforce() || cache->permissive)
			cache->allowed |= required;		/* prevent flood of audit log */
		else
		{
			if (abort)
				ereport(ERROR,
						(errcode(ERRCODE_SELINUX_ERROR),
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
	sepgsql_sid_t	nsid;
	avc_datum	   *cache;
	int				index;

	do {
		cache = sepgsqlAvcLookup(current_page, tsid, tclass);
		if (!cache)
			cache = sepgsqlAvcMakeEntry(current_page, tsid, tclass);

		index = (nrelid % AVC_DATUM_NSID_SLOTS);
		if (cache->nsid[index].relid != nrelid)
		{
			cache->nsid[index].secid
				= securityRawSecLabelIn(nrelid, cache->ncontext);
			cache->nsid[index].relid = nrelid;
		}
		nsid = cache->nsid[index];
	} while (!sepgsqlAvcCheckValid());

	return nsid;
}

security_context_t
sepgsqlClientCreateLabel(sepgsql_sid_t tsid, uint16 tclass)
{
	avc_datum  *cache;

	do {
		cache = sepgsqlAvcLookup(current_page, tsid, tclass);
		if (!cache)
			cache = sepgsqlAvcMakeEntry(current_page, tsid, tclass);
	} while (!sepgsqlAvcCheckValid());

	return cache->ncontext;
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
	if (!denied ||					/* no policy violation */
		!sepgsqlGetEnforce() ||		/* permissive mode */
		(avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE) != 0)	/* permissive domain */
		return true;

	if (abort)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: security policy violation")));

	return false;
}

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
	sepgsqlShmemInit();

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
