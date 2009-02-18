/*
 * src/backend/utils/sepgsql/avc.c
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

/*
 * Dynamic object class/access vector mapping
 *
 * SELinux exports the list of object classes (it means kind of object, like
 * file or table) and access vectors (it means permission set, like read,
 * select, ...) under /selinux/class.
 * It enables to provide userspace object managers a interface to get what
 * codes should be used to ask SELinux.
 *
 * libselinux provides an API to translate a string expression and a code
 * used by the loaded security policy. These correspondences are not assured
 * over the bound of policy loading, so we have to reload the mapping after
 * in-kernel policy is reloaded, or its state is changed.
 */
static struct
{
	struct
	{
		const char *name;
		security_class_t internal;
	} tclass;
	struct
	{
		char	   *name;
		access_vector_t internal;
	} av_perms[sizeof(access_vector_t) * 8];
} selinux_catalog[] = {
	{
		{ "db_database", SECCLASS_DB_DATABASE},
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
			{ NULL, 0UL },
		}
	},
	{
		{ "db_table", SECCLASS_DB_TABLE},
		{
			{ "create",			DB_TABLE__CREATE },
			{ "drop",			DB_TABLE__DROP },
			{ "getattr",		DB_TABLE__GETATTR },
			{ "setattr",		DB_TABLE__SETATTR },
			{ "relabelfrom",	DB_TABLE__RELABELFROM },
			{ "relabelto",		DB_TABLE__RELABELTO },
			{ "use",   			DB_TABLE__USE },
			{ "select",			DB_TABLE__SELECT },
			{ "update",			DB_TABLE__UPDATE },
			{ "insert",			DB_TABLE__INSERT },
			{ "delete",			DB_TABLE__DELETE },
			{ "lock",			DB_TABLE__LOCK },
			{ NULL, 0UL },
		}
	},
	{
		{ "db_procedure", SECCLASS_DB_PROCEDURE},
		{
			{ "create",			DB_PROCEDURE__CREATE },
			{ "drop",			DB_PROCEDURE__DROP },
			{ "getattr",		DB_PROCEDURE__GETATTR },
			{ "setattr",		DB_PROCEDURE__SETATTR },
			{ "relabelfrom",	DB_PROCEDURE__RELABELFROM },
			{ "relabelto",		DB_PROCEDURE__RELABELTO },
			{ "execute",		DB_PROCEDURE__EXECUTE },
			{ "entrypoint",		DB_PROCEDURE__ENTRYPOINT },
			{ "install",		DB_PROCEDURE__INSTALL },
			{ NULL, 0UL },
		}
	},
	{
		{ "db_column", SECCLASS_DB_COLUMN},
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
			{ NULL, 0UL },
		}
	},
	{
		{ "db_tuple", SECCLASS_DB_TUPLE },
		{
			{ "relabelfrom",	DB_TUPLE__RELABELFROM},
			{ "relabelto",		DB_TUPLE__RELABELTO},
			{ "use",			DB_TUPLE__USE},
			{ "select",			DB_TUPLE__SELECT},
			{ "update",			DB_TUPLE__UPDATE},
			{ "insert",			DB_TUPLE__INSERT},
			{ "delete",			DB_TUPLE__DELETE},
			{ NULL, 0UL},
		}
	},
	{
		{ "db_blob", SECCLASS_DB_BLOB },
		{
			{ "create",			DB_BLOB__CREATE},
			{ "drop",			DB_BLOB__DROP},
			{ "getattr",		DB_BLOB__GETATTR},
			{ "setattr",		DB_BLOB__SETATTR},
			{ "relabelfrom",	DB_BLOB__RELABELFROM},
			{ "relabelto",		DB_BLOB__RELABELTO},
			{ "read",			DB_BLOB__READ},
			{ "write",			DB_BLOB__WRITE},
			{ "import",			DB_BLOB__IMPORT},
			{ "export",			DB_BLOB__EXPORT},
			{ NULL, 0UL},
		}
	},
};

static MemoryContext AvcMemCtx;

#define AVC_HASH_NUM_SLOTS		256
#define AVC_HASH_NUM_NODES		180

static sig_atomic_t avc_version;
static bool avc_enforcing;

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
 * The most significant variable is selinux_state->version.
 * Any instance can refer this variable to confirm current sequence
 * number of policy state, without locking.
 * 
 * The only process able to update this variable is policy state
 * monitoring process forked by postmaster. It can receive notifications
 * from the kernel via netlink socket, and it update selinux_state->version
 * to encourage any instance to reflush its uAVC.
 *
 * When we read rest of variable, we have to hold SepgsqlAvcLock LWlock
 * as a reader. enforceing shows the current SELinux working mode.
 * catalog shows the mapping set of security classes and access vectors.
 */
struct
{
	/*
	 * only state monitoring process can update version.
	 * any other process can read it without locks.
	 */
	volatile sig_atomic_t version;

	bool		enforcing;

	struct
	{
		struct
		{
			security_class_t internal;
			security_class_t external;
		} tclass;
		struct
		{
			access_vector_t internal;
			access_vector_t external;
		} av_perms[sizeof(access_vector_t) * 8];
	} catalog[lengthof(selinux_catalog)];
}	*selinux_state = NULL;

Size
sepgsqlShmemSize(void)
{
	if (!sepgsqlIsEnabled())
		return 0;

	return sizeof(*selinux_state);
}

/*
 * load_class_av_mapping
 *
 * This function rebuild the mapping set of security classes and access
 * vectors on selinux_state. It has to be invoked by the policy state
 * monitoring process with SepgsqlAvcLock in LW_EXCLUSIVE.
 */
static void
load_class_av_mapping(void)
{
	int			i, j;

	memset(selinux_state->catalog, 0, sizeof(selinux_state->catalog));

	for (i = 0; i < lengthof(selinux_catalog); i++)
	{
		selinux_state->catalog[i].tclass.internal
			= selinux_catalog[i].tclass.internal;
		selinux_state->catalog[i].tclass.external
			= string_to_security_class(selinux_catalog[i].tclass.name);

		for (j = 0; selinux_catalog[i].av_perms[j].name; j++)
		{
			selinux_state->catalog[i].av_perms[j].internal
				= selinux_catalog[i].av_perms[j].internal;
			selinux_state->catalog[i].av_perms[j].external
				= string_to_av_perm(selinux_state->catalog[i].tclass.external,
									selinux_catalog[i].av_perms[j].name);
		}
	}
}

/*
 * trans_to_external_tclass
 *   translates internal object class number into external one
 *   needed to communicate with in-kernel SELinux.
 */
static security_class_t
trans_to_external_tclass(security_class_t i_tclass)
{
	/* have to hold SepgsqlAvcLock with LW_SHARED */
	int			i;

	for (i = 0; i < lengthof(selinux_catalog); i++)
	{
		if (selinux_state->catalog[i].tclass.internal == i_tclass)
			return selinux_state->catalog[i].tclass.external;
	}
	return i_tclass;			/* use it as is for kernel classes */
}

/*
 * trans_to_internal_perms
 *   translates external permission bits into internal ones
 *   needed to understand the answer from in-kernel SELinux.
 *   If in-kernel SELinux doesn't define required permissions,
 *   it sets/clears undefined bits based on caller's preference.
 *   It enables SE-PostgreSQL to work on legacy security policy.
 */
static access_vector_t
trans_to_internal_perms(security_class_t e_tclass, access_vector_t e_perms,
						bool set_if_undefined)
{
	/* have to hold SepgsqlAvcLock with LW_SHARED */
	access_vector_t i_perms = 0UL;
	access_vector_t undef_mask = 0UL;
	int			i, j;

	for (i = 0; i < lengthof(selinux_catalog); i++)
	{
		if (selinux_state->catalog[i].tclass.external != e_tclass)
			continue;

		for (j = 0; j < sizeof(access_vector_t) * 8; j++)
		{
			if (selinux_state->catalog[i].av_perms[j].external == 0)
				undef_mask |= (1UL << j);
			else if (selinux_state->catalog[i].av_perms[j].external & e_perms)
				i_perms |= selinux_state->catalog[i].av_perms[j].internal;
		}

		if (set_if_undefined)
			i_perms |= undef_mask;
		else
			i_perms &= ~undef_mask;

		return i_perms;
	}
	return e_perms;				/* use it as is for kernel classes */
}

/*
 * sepgsql_class_to_string
 * sepgsql_av_perm_to_string
 *   returns string representation of given object class and permission.
 *   Please note that given code have internal ones, so we cannot use
 *   libselinux's facility, because it assumes 'external code'.
 *   (Kernel object classes are ABI, so these are stable.)
 */
static const char *
sepgsql_class_to_string(security_class_t tclass)
{
	int			i;

	for (i = 0; i < lengthof(selinux_catalog); i++)
	{
		if (selinux_catalog[i].tclass.internal == tclass)
			return selinux_catalog[i].tclass.name;
	}
	/*
	 * tclass is stable for kernel object classes.
	 */
	return security_class_to_string(tclass);
}

static const char *
sepgsql_av_perm_to_string(security_class_t tclass, access_vector_t perm)
{
	int			i, j;

	for (i = 0; i < lengthof(selinux_catalog); i++)
	{
		if (selinux_catalog[i].tclass.internal == tclass)
		{
			char	   *perm_name;

			for (j = 0; (perm_name = selinux_catalog[i].av_perms[j].name); j++)
			{
				if (selinux_catalog[i].av_perms[j].internal == perm)
					return perm_name;
			}
			return "unknown";
		}
	}
	/*
	 * tclass/perms are stable for kernel object classes.
	 */
	return security_av_perm_to_string(tclass, perm);
}

/*
 * sepgsql_avc_reset
 *   clears all uAVC entries and update its version.
 */
static void
sepgsql_avc_reset(void)
{
	MemoryContextReset(AvcMemCtx);

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);

	avc_version = selinux_state->version;
	avc_enforcing = selinux_state->enforcing;
	client_avc_page = NULL;

	LWLockRelease(SepgsqlAvcLock);

	sepgsqlAvcSwitchClient();
}

/*
 * sepgsql_avc_reclaim
 *   reclaims recently unused uAVC entries, when the number of
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
							sepgsql_av_perm_to_string(tclass, mask));
		audited &= ~mask;
	}
	ofs += snprintf(buffer + ofs, buflen - ofs, " } ");

	ofs += snprintf(buffer + ofs, buflen - ofs,
					"scontext=%s tcontext=%s tclass=%s",
					scontext, tcontext,
					sepgsql_class_to_string(tclass));

	if (audit_name)
		ofs += snprintf(buffer + ofs, buflen - ofs, " name=%s", audit_name);
}

/*
 * avc_make_entry
 *   makes a query to in-kernel SELinux and an avc_datum object to
 *   cache the result of SELinux's decision for access rights and
 *   default security context.
 */
#define avc_hash_key(tsid, tclass)		((tsid) ^ ((tclass) << 3))

static avc_datum *
avc_make_entry(avc_page *page, sepgsql_sid_t tsid, security_class_t tclass)
{
	security_context_t scontext, tcontext, ncontext;
	security_class_t e_tclass;
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

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);

	e_tclass = trans_to_external_tclass(tclass);

	if (security_compute_av_raw(scontext, tcontext, e_tclass, 0, &avd) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute av_decision: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsql_class_to_string(tclass))));

	cache->allowed = trans_to_internal_perms(e_tclass, avd.allowed, true);
	cache->decided = trans_to_internal_perms(e_tclass, avd.decided, false);
	cache->auditallow = trans_to_internal_perms(e_tclass, avd.auditallow, false);
	cache->auditdeny = trans_to_internal_perms(e_tclass, avd.auditdeny, false);
	cache->hot_cache = true;

	if (security_compute_create_raw(scontext, tcontext, e_tclass, &ncontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute new context: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsql_class_to_string(tclass))));

	LWLockRelease(SepgsqlAvcLock);

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

static avc_datum *
avc_lookup(avc_page *page, sepgsql_sid_t tsid, security_class_t tclass)
{
	avc_datum *cache = NULL;
	uint32 hash_key, index;
	ListCell *l;

	/* check avc invalidation */
	if (avc_version != selinux_state->version)
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
sepgsqlClientHasPerms(sepgsql_sid_t tsid,
					  security_class_t tclass,
					  access_vector_t required,
					  const char *audit_name, bool abort)
{
	char audit_buffer[2048];
	access_vector_t denied, audited;
	avc_datum *cache;
	bool rc = true;

	cache = avc_lookup(client_avc_page, tsid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page, tsid, tclass);

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
		if (avc_enforcing)
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
 *   returns security identifier of newly created database object.
 *   Please note that you don't have to invoke this function for
 *   object classes except for database objects. It have a possibility
 *   to make an entry on pg_security via pgaceSecurityLabelToSid(),
 *   but it should be restricted to database object.
 */
sepgsql_sid_t
sepgsqlClientCreate(sepgsql_sid_t tsid, security_class_t tclass)
{
	avc_datum *cache;

	cache = avc_lookup(client_avc_page, tsid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page, tsid, tclass);

	return securityLookupSecurityId(cache->ncontext);
}

/*
 * sepgsqlClientCreateLabel
 *   returns security context in text form of newly created object.
 *   In the current version, it is same as sepgsqlClientCreate()
 */
security_context_t
sepgsqlClientCreateLabel(sepgsql_sid_t tsid, security_class_t tclass)
{
	avc_datum *cache;

	cache = avc_lookup(client_avc_page, tsid, tclass);
	if (!cache)
		cache = avc_make_entry(client_avc_page, tsid, tclass);

	return pstrdup(cache->ncontext);
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
		int enforcing = security_getenforce();

		Assert(enforcing == 0 || enforcing == 1);

		LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
		selinux_state->version = 0;
		selinux_state->enforcing = enforcing;
		load_class_av_mapping();

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
	security_class_t eclass;
	struct av_decision avd;
	char audit_buffer[2048];
	bool rc = true;

	scontext = (!security_check_context_raw(scontext)
				? scontext : sepgsqlGetUnlabeledLabel());
	tcontext = (!security_check_context_raw(tcontext)
				? tcontext : sepgsqlGetUnlabeledLabel());

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	eclass = trans_to_external_tclass(tclass);

	if (security_compute_av_raw(scontext, tcontext, eclass, 0, &avd) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute an av_decision"
						" scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, security_class_to_string(eclass))));

	avd.allowed = trans_to_internal_perms(eclass, avd.allowed, true);
	avd.decided = trans_to_internal_perms(eclass, avd.decided, false);
	avd.auditallow = trans_to_internal_perms(eclass, avd.auditallow, false);
	avd.auditdeny = trans_to_internal_perms(eclass, avd.auditdeny, false);
	LWLockRelease(SepgsqlAvcLock);

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
		if (avc_enforcing)
			rc = false;
	}

	if (audited)
	{
		ereport((!rc && abort) ? ERROR : NOTICE,
				(errcode(ERRCODE_SELINUX_AUDIT),
				 errmsg("SELinux: %s", audit_buffer)));
	}
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
	security_class_t eclass;

	scontext = (!security_check_context_raw(scontext)
				? scontext : sepgsqlGetUnlabeledLabel());
	tcontext = (!security_check_context_raw(tcontext)
				? tcontext : sepgsqlGetUnlabeledLabel());

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	eclass = trans_to_external_tclass(tclass);
	LWLockRelease(SepgsqlAvcLock);

	if (security_compute_create_raw(scontext, tcontext, eclass, &ncontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute a default context"
						" scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, security_class_to_string(eclass))));
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

static bool sepgsqlStateMonitorAlive = true;

static void
sepgsqlStateMonitorSIGHUP(SIGNAL_ARGS)
{
	ereport(NOTICE,
			(errcode(ERRCODE_SELINUX_INFO),
			 errmsg("SELinux: invalidate userspace avc")));
	selinux_state->version = selinux_state->version + 1;
}

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
	pqsignal(SIGHUP, sepgsqlStateMonitorSIGHUP);
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
	while (sepgsqlStateMonitorAlive)
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

					LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
					load_class_av_mapping();

					/*
					 * userspace avc invalidation
					 */
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

					LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
					load_class_av_mapping();
					/*
					 * userspace avc invalidation
					 */
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
