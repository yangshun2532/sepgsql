/*
 * src/backend/security/sepgsql/avc.c
 *	  SE-PostgreSQL userspace access vector cache
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
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

/*
 * uAVC: userspace Access Vector Cache
 *
 * SE-PostgreSQL makes inqueries for SELinux to check whether the security
 * policy allows the required action, or not. However, it need to invoke
 * system call because SELinux is a kernel feature and it hold its security
 * policy in the kernel memory.
 *
 * uAVC enables to reduce the number of kernel invocation, with caching
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

#define NUM_SELINUX_CATALOG (sizeof(selinux_catalog) / sizeof(selinux_catalog[0]))

static MemoryContext AvcMemCtx;

#define AVC_HASH_NUM_SLOTS		256
#define AVC_HASH_NUM_NODES		600

static sig_atomic_t avc_version;
static bool avc_enforcing;

typedef struct
{
	uint32	hash_key;

	security_class_t tclass;
	Oid		tsid;	/* target security context */

	security_context_t ncontext;	/* newcontext */
	Oid		nsid;	/* newly created security context */

	access_vector_t allowed;
	access_vector_t decided;
	access_vector_t auditallow;
	access_vector_t auditdeny;

	bool	hot_cache;
} avc_datum;

typedef struct avc_page
{
	struct avc_page *prev;
	struct avc_page *next;

	security_context_t	scontext;

	List *slot[AVC_HASH_NUM_SLOTS];

	uint32 lru_hint;
} avc_page;

static avc_page *current_avc_page = NULL;
static uint32 avc_datum_count = 0;

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
	} catalog[NUM_SELINUX_CATALOG];
}	*selinux_state = NULL;

Size
sepgsqlShmemSize(void)
{
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
	security_class_t tclass;
	access_vector_t av_perms;
	int			i, j;

	for (i = 0; i < NUM_SELINUX_CATALOG; i++)
	{
		tclass = string_to_security_class(selinux_catalog[i].tclass.name);
		if (!tclass)
			tclass = selinux_catalog[i].tclass.internal;

		selinux_state->catalog[i].tclass.internal
			= selinux_catalog[i].tclass.internal;
		selinux_state->catalog[i].tclass.external = tclass;

		for (j = 0; selinux_catalog[i].av_perms[j].name; j++)
		{
			av_perms =
				string_to_av_perm(tclass, selinux_catalog[i].av_perms[j].name);
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
	int			i;

	for (i = 0; i < NUM_SELINUX_CATALOG; i++)
	{
		if (selinux_state->catalog[i].tclass.internal == i_tclass)
			return selinux_state->catalog[i].tclass.external;
	}
	return i_tclass;			/* use it as is for kernel classes */
}

static access_vector_t
trans_to_internal_perms(security_class_t e_tclass, access_vector_t e_perms)
{
	/* have to hold SepgsqlAvcLock with LW_SHARED */
	access_vector_t i_perms = 0UL;
	int			i, j;

	for (i = 0; i < NUM_SELINUX_CATALOG; i++)
	{
		if (selinux_state->catalog[i].tclass.external != e_tclass)
			continue;
		for (j = 0; j < sizeof(access_vector_t) * 8; j++)
		{
			if ((selinux_state->catalog[i].av_perms[j].external & e_perms) != 0)
				i_perms |= selinux_state->catalog[i].av_perms[j].internal;
		}
		return i_perms;
	}
	return e_perms;				/* use it as is for kernel classes */
}

static const char *
sepgsql_class_to_string(security_class_t tclass)
{
	int			i;

	for (i = 0; i < NUM_SELINUX_CATALOG; i++)
	{
		if (selinux_catalog[i].tclass.internal == tclass)
			return selinux_catalog[i].tclass.name;
	}
	/*
	 * tclass is always same as external one, for kernel object classes
	 */
	return security_class_to_string(tclass);
}

static const char *
sepgsql_av_perm_to_string(security_class_t tclass, access_vector_t perm)
{
	int			i, j;

	for (i = 0; i < NUM_SELINUX_CATALOG; i++)
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
	 * tclass is always same as external one, for kernel object classes
	 */
	return security_av_perm_to_string(tclass, perm);
}

/*
 * sepgsql_avc_reset
 *
 * This function clears all current avc entries, and update its version.
 */
static void
sepgsql_avc_reset(void)
{
	MemoryContextReset(AvcMemCtx);

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);

	avc_version = selinux_state->version;
	switch (sepostgresql_mode)
	{
	case SEPGSQL_MODE_DEFAULT:
		avc_enforcing = selinux_state->enforcing;
		break;
	case SEPGSQL_MODE_PERMISSIVE:
		avc_enforcing = false;
		break;
	case SEPGSQL_MODE_ENFORCING:
		avc_enforcing = false;
		break;
	default:
		elog(FATAL, "SELinux: undefined state in SE-PostgreSQL");
		break;
	}

	current_avc_page = NULL;

	LWLockRelease(SepgsqlAvcLock);

	sepgsqlAvcSwitchClientContext(sepgsqlGetClientContext());
}

/*
 * sepgsql_avc_reclaim
 *
 * This function reclaims recently not-used avc entries,
 * when the number of caches overs AVC_HASH_NUM_NODES
 */
static void
sepgsql_avc_reclaim(void)
{
	ListCell *l;
	avc_page *avp;
	avc_datum *cache;
	int loop;

	Assert(current_avc_page != NULL);

	for (avp = current_avc_page->next; true; avp = avp->next)
	{
		for (loop = 0; loop < AVC_HASH_NUM_SLOTS; loop++)
		{
			if (avc_datum_count < AVC_HASH_NUM_NODES)
				return;

			avp->lru_hint = (avp->lru_hint + 1) % AVC_HASH_NUM_SLOTS;
			foreach (l, avp->slot[avp->lru_hint])
			{
				cache = lfirst(l);

				if (cache->hot_cache)
				{
					cache->hot_cache = false;
					continue;
				}

				list_delete_ptr(avp->slot[avp->lru_hint], cache);
				pfree(cache);
				avc_datum_count--;
			}
		}
	}
}

/*
 * avc_audit_common
 *
 * This function makes an audit message on the given Cstring buffer,
 * based on the given av_decision (which is the result of permission
 * checks).
 */
static bool
avc_audit_common(char *buffer, uint32 buflen,
				 avc_datum *cache, access_vector_t perms,
				 const char *scontext, const char *tcontext, const char *objname)
{
	access_vector_t denied, audited, mask;
	security_context_t svcon, tvcon;
	uint32 ofs = 0;

	denied = perms & ~cache->allowed;
	audited = denied ? (denied & cache->auditdeny) : (perms & cache->auditallow);

	if (audited == 0)
		return false;

	ofs += snprintf(buffer + ofs, buflen - ofs, "%s {",
					denied ? "denied" : "granted");
	for (mask = 1; mask != 0; mask <<= 1)
	{
		if ((audited & mask) != 0)
			ofs += snprintf(buffer + ofs, buflen - ofs, " %s",
							sepgsql_av_perm_to_string(cache->tclass, mask));
	}
	ofs += snprintf(buffer + ofs, buflen - ofs, " } ");

	if (!scontext)
		svcon = sepgsqlTranslateSecurityLabelOut(current_avc_page->scontext);
	else
		svcon = sepgsqlTranslateSecurityLabelOut(scontext);

	if (!tcontext)
		tvcon = pgaceSidToSecurityLabel(cache->tsid);
	else
		tvcon = sepgsqlTranslateSecurityLabelOut(tcontext);

	ofs += snprintf(buffer + ofs, buflen - ofs,
					"scontext=%s tcontext=%s tclass=%s",
					svcon, tvcon, sepgsql_class_to_string(cache->tclass));

	pfree(svcon);
	pfree(tvcon);
	if (objname)
		ofs += snprintf(buffer + ofs, buflen - ofs, " name=%s", objname);

	return true;
}

static bool
avc_permission_common(avc_datum *cache, access_vector_t perms, bool abort,
					  const char *scontext, const char *tcontext, const char *objname)
{
	char audit_buffer[2048];
	access_vector_t denied;
	bool audit;
	bool rc = true;

	audit = avc_audit_common(audit_buffer, sizeof(audit_buffer),
							 cache, perms, scontext, tcontext, objname);

	denied = perms & ~cache->allowed;
	if (!perms || denied)
	{
		if (avc_enforcing)
			rc = false;
		else
		{
			/*
			 * In permissive mode, once denied permissions are
			 * allowed to avoid a flood of denied logs.
			 */
			cache->allowed |= perms;
		}
	}

	if (audit)
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

/*
 * sepgsql_avc_compute
 *
 * This function compute an avc_decision cache for the given subject/target
 * context and object class, based on results of inquiries to SELinux.
 */
#define avc_hash_key(tsid,tclass)	((tsid) ^ ((tclass) << 2))

static avc_datum *avc_make_entry(Oid tsid, security_class_t tclass)
{
	security_context_t scontext, tcontext, ncontext;
	security_class_t e_tclass;
	MemoryContext oldctx = MemoryContextSwitchTo(AvcMemCtx);
	struct av_decision avd;
	avc_datum *cache;
	uint32 hash_key, index;

	hash_key = avc_hash_key(tsid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	cache = palloc0(sizeof(avc_datum));
	cache->hash_key = hash_key;
	cache->tsid = tsid;
	cache->tclass = tclass;

	scontext = current_avc_page->scontext;
	tcontext = pgaceLookupSecurityLabel(tsid);
	if (!tcontext || !pgaceCheckValidSecurityLabel(tcontext))
		tcontext = pgaceUnlabeledSecurityLabel();

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);

	e_tclass = trans_to_external_tclass(tclass);

	if (security_compute_av_raw(scontext, tcontext, e_tclass, 0, &avd) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute av_decision: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsql_class_to_string(tclass))));

	if (security_compute_create_raw(scontext, tcontext, e_tclass, &ncontext) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute new context: "
						"scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, sepgsql_class_to_string(tclass))));
	pfree(tcontext);

	cache->allowed = trans_to_internal_perms(e_tclass, avd.allowed);
	cache->decided = trans_to_internal_perms(e_tclass, avd.decided);
	cache->auditallow = trans_to_internal_perms(e_tclass, avd.auditallow);
	cache->auditdeny = trans_to_internal_perms(e_tclass, avd.auditdeny);
	cache->hot_cache = true;

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

	sepgsql_avc_reclaim();

	current_avc_page->slot[index]
		= lcons(cache, current_avc_page->slot[index]);

	MemoryContextSwitchTo(oldctx);

	return cache;
}

static avc_datum *avc_lookup(Oid tsid, security_class_t tclass)
{
	avc_datum *cache = NULL;
	uint32 hash_key, index;
	ListCell *l;

	/*
	 * check avc invalidation
	 */
	if (avc_version != selinux_state->version)
		sepgsql_avc_reset();

	/*
	 * lookup avc entry
	 */
	hash_key = avc_hash_key(tsid, tclass);
	index = hash_key % AVC_HASH_NUM_SLOTS;

	foreach (l, current_avc_page->slot[index])
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
 * sepgsqlAvcSwitchClientContext()
 *
 * This function switchs avc_page for given context
 */
void sepgsqlAvcSwitchClientContext(security_context_t newcontext)
{
	MemoryContext oldctx;
	avc_page *avp;
	int i;

	if (current_avc_page)
	{
		avp = current_avc_page;
		do {
			if (!strcmp(avp->scontext, newcontext))
			{
				current_avc_page = avp;
				return;
			}
			avp = avp->next;
		} while (avp != current_avc_page);
	}

	/* create a new avc_page */
	oldctx = MemoryContextSwitchTo(AvcMemCtx);
	avp = palloc0(sizeof(avc_page));
	avp->scontext = pstrdup(newcontext);
	MemoryContextSwitchTo(oldctx);

	for (i=0; i < AVC_HASH_NUM_SLOTS; i++)
		avp->slot[i] = NIL;

	if (!current_avc_page)
	{
		avp->next = avp->prev = avp;
	}
	else
	{
		avp->next = current_avc_page;
		avp->prev = current_avc_page->prev;
		avp->prev->next = avp;
		avp->next->prev = avp;
	}
	current_avc_page = avp;
}

void
sepgsqlClientHasPermission(Oid tsid, security_class_t tclass,
						   access_vector_t perms,
						   const char *objname)
{
	avc_datum *cache = avc_lookup(tsid, tclass);

	if (!cache)
		cache = avc_make_entry(tsid, tclass);

	avc_permission_common(cache, perms, true, NULL, NULL, objname);
}

bool
sepgsqlClientHasPermissionNoAbort(Oid tsid, security_class_t tclass,
								  access_vector_t perms,
								  const char *objname)
{
	avc_datum *cache = avc_lookup(tsid, tclass);

	if (!cache)
		cache = avc_make_entry(tsid, tclass);

	return avc_permission_common(cache, perms, false, NULL, NULL, objname);
}

Oid
sepgsqlClientCreateSid(Oid tsid, security_class_t tclass)
{
	avc_datum *cache = avc_lookup(tsid, tclass);

	if (!cache || cache->nsid == InvalidOid)
	{
		if (!cache)
			cache = avc_make_entry(tsid, tclass);
		cache->nsid = pgaceSecurityLabelToSid(cache->ncontext);
	}
	return cache->nsid;
}

security_context_t
sepgsqlClientCreateContext(Oid tsid, security_class_t tclass)
{
	avc_datum *cache = avc_lookup(tsid, tclass);

	if (!cache)
		cache = avc_make_entry(tsid, tclass);

	return pstrdup(cache->ncontext);
}

/*
 * sepgsqlAvcInit
 *
 * Initialize local memory context and assign shared memory segment
 */
static void
sepgsql_shmem_init(void)
{
	bool found;

	selinux_state = ShmemInitStruct("SELinux policy state",
									sepgsqlShmemSize(), &found);
	if (!found)
	{
		int			enforcing = security_getenforce();

		Assert(enforcing == 0 || enforcing == 1);

		LWLockAcquire(SepgsqlAvcLock, LW_EXCLUSIVE);
		selinux_state->version = 0;
		selinux_state->enforcing = enforcing;
		load_class_av_mapping();

		LWLockRelease(SepgsqlAvcLock);
	}
}

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
 * No cached interfaces
 */
bool
sepgsqlComputePermission(const security_context_t scontext,
						 const security_context_t tcontext,
						 security_class_t tclass,
						 access_vector_t perms,
						 const char *objname)
{
	security_context_t svcon, tvcon;
	security_class_t e_tclass;
	struct av_decision avd;
	avc_datum cache;
	bool rc;

	svcon = (!security_check_context_raw(scontext)
			 ? scontext : sepgsqlGetUnlabeledContext());
	tvcon = (!security_check_context_raw(tcontext)
			 ? tcontext : sepgsqlGetUnlabeledContext());

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	e_tclass = trans_to_external_tclass(tclass);

	if (security_compute_av_raw(svcon, tvcon, e_tclass, 0, &avd) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute an av_decision"
						" scontext=%s tcontext=%s tclass=%s",
						svcon, tvcon, security_class_to_string(e_tclass))));

	cache.tclass = tclass;
	cache.allowed = trans_to_internal_perms(e_tclass, avd.allowed);
	cache.decided = trans_to_internal_perms(e_tclass, avd.decided);
	cache.auditallow = trans_to_internal_perms(e_tclass, avd.auditallow);
	cache.auditdeny = trans_to_internal_perms(e_tclass, avd.auditdeny);
	LWLockRelease(SepgsqlAvcLock);

	rc = avc_permission_common(&cache, perms, true, svcon, tvcon, objname);

	if (svcon != scontext)
		pfree(svcon);
	if (tvcon != tcontext)
		pfree(tvcon);

	return rc;
}

security_context_t
sepgsqlComputeCreateContext(const security_context_t scontext,
							const security_context_t tcontext,
							security_class_t tclass)
{
	security_context_t svcon, tvcon, nwcon, copy;
	security_class_t e_tclass;

	svcon = (!security_check_context_raw(scontext)
			 ? scontext : sepgsqlGetUnlabeledContext());
	tvcon = (!security_check_context_raw(tcontext)
			 ? tcontext : sepgsqlGetUnlabeledContext());

	LWLockAcquire(SepgsqlAvcLock, LW_SHARED);
	e_tclass = trans_to_external_tclass(tclass);

	if (security_compute_create_raw(svcon, tvcon, e_tclass, &nwcon) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_SELINUX_ERROR),
				 errmsg("SELinux: could not compute a default context"
						" scontext=%s tcontext=%s tclass=%s",
						scontext, tcontext, security_class_to_string(e_tclass))));

	LWLockRelease(SepgsqlAvcLock);

	if (svcon != scontext)
		pfree(svcon);
	if (tvcon != tcontext)
		pfree(tvcon);

	PG_TRY();
	{
		copy = pstrdup(nwcon);
	}
	PG_CATCH();
	{
		freecon(nwcon);
		PG_RE_THROW();
	}
	PG_END_TRY();

	freecon(nwcon);

	return copy;
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
