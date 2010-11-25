/*
 * uavc.c
 *
 * userspace access vector cache
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * Copyright (c) 2007 - 2010, NEC Corporation
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"
#include "access/hash.h"
#include "commands/seclabel.h"
#include "utils/memutils.h"
#include "sepgsql.h"

#include <sched.h>
#include <selinux/avc.h>
#include <sys/mman.h>
#include <unistd.h>

extern const char *selinux_mnt;

static MemoryContext avc_mem_cxt = NULL;

#define AVC_HASH_NUM_SLOTS	256
#define AVC_HASH_NUM_NODES	320

typedef struct avc_datum
{
	uint32				hash;

	security_class_t	tclass;
	ObjectAddress		tobject;

	access_vector_t		allowed;
	access_vector_t		auditallow;
	access_vector_t		auditdeny;

	bool				hot_cache;
	bool				permissive;

	char				ncontext[1];
} avc_datum;

typedef struct avc_page
{
	struct avc_page	   *next;

	List			   *slot[AVC_HASH_NUM_SLOTS];

	uint32				avc_count;
	uint32				lru_hint;

	char				scontext[1];
} avc_page;

static avc_page	   *client_avc_page = NULL;

static struct
{
	int				fdesc;
	struct
	{
		uint32		version;
		uint32		sequence;
		uint32		enforcing;
		uint32		policyload;
		uint32		deny_unknown;
	}  *kernel;
	uint32			last_seqno;
	uint32			curr_seqno;	/* used to netlink callback */
} selinux_state;


static void
sepgsql_avc_reset(void)
{
	MemoryContextReset(avc_mem_cxt);

	client_avc_page = NULL;

	sepgsql_avc_switch_client();
}

static void
sepgsql_avc_reclaim(avc_page *page)
{
	ListCell   *l;
	avc_datum  *cache;

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

#define sepgsql_avc_hash(tobject, tclass)					\
	hash_uint32((tobject)->classId ^ (tobject)->objectId ^	\
				(tobject)->objectSubId ^ ((tclass) << 3))	\

static avc_datum *
sepgsql_avc_make_entry(avc_page		   *page,
					   ObjectAddress   *tobject,
					   security_class_t	tclass)
{
	struct av_decision	avd;
	MemoryContext		oldcxt;
	security_context_t	scontext;
	security_context_t	tcontext;
	security_context_t	ncontext;
	avc_datum		   *cache;
	uint32				hash;
	uint32				index;

	hash = sepgsql_avc_hash(tobject, tclass);
	index = hash % AVC_HASH_NUM_SLOTS;

	scontext = page->scontext;
	tcontext = GetSecurityLabel(tobject, SEPGSQL_LABEL_TAG);

	sepgsql_compute_avd(scontext, tcontext, tclass, &avd);

	ncontext = sepgsql_compute_create(scontext, tcontext, tclass);

	oldcxt = MemoryContextSwitchTo(avc_mem_cxt);

	cache = palloc0(sizeof(avc_datum) + strlen(ncontext));

	cache->hash = hash;
	cache->tclass = tclass;
	memcpy(&cache->tobject, tobject, sizeof(ObjectAddress));

	cache->allowed = avd.allowed;
	cache->auditallow = avd.auditallow;
	cache->auditdeny = avd.auditdeny;

	cache->hot_cache = true;
	if (avd.flags & SELINUX_AVD_FLAGS_PERMISSIVE)
		cache->permissive = true;

	strcpy(cache->ncontext, ncontext);
	pfree(ncontext);

	sepgsql_avc_reclaim(page);

	page->slot[index] = lcons(cache, page->slot[index]);
	page->avc_count++;

	MemoryContextSwitchTo(oldcxt);

	return cache;
}

static avc_datum *
sepgsql_avc_lookup(avc_page		   *page,
				   ObjectAddress   *tobject,
				   security_class_t	tclass)
{
	avc_datum  *cache;
	uint32		hash;
	uint32		index;
	ListCell   *l;

	hash = sepgsql_avc_hash(tobject, tclass);
	index = hash % AVC_HASH_NUM_SLOTS;

	foreach (l, page->slot[index])
	{
		cache = lfirst(l);
		if (cache->hash == hash &&
			cache->tclass == tclass &&
			memcmp(&cache->tobject, tobject, sizeof(ObjectAddress)) == 0)
		{
			cache->hot_cache = true;
			return cache;
		}
	}
	return NULL;
}

bool
sepgsql_client_has_perms(ObjectAddress	   *tobject,
						 security_class_t	tclass,
						 access_vector_t	required,
						 const char		   *audit_name,
						 bool				abort)
{
	security_context_t	scontext;
	security_context_t	tcontext;
	access_vector_t		denied;
	access_vector_t		audited;
	avc_datum		   *cache;
	bool				result = true;

	sepgsql_avc_check_valid();
	do {
		cache = sepgsql_avc_lookup(client_avc_page, tobject, tclass);
		if (!cache)
			cache = sepgsql_avc_make_entry(client_avc_page, tobject, tclass);

		denied	= required & ~cache->allowed;
		if (sepgsql_debug_audit)
			audited = (denied ? (denied & ~0) : (required & ~0));
		else
			audited	= denied ? (denied & cache->auditdeny)
							 : (required & cache->auditallow);
		if (denied)
		{
			if (!sepgsql_avc_getenforce() || cache->permissive)
				cache->allowed |= required;
			else
				result = false;
		}
	} while (!sepgsql_avc_check_valid());

	if (audited && sepgsql_mode != SEPGSQL_MODE_INTERNAL)
	{
		scontext = client_avc_page->scontext;
		tcontext = GetSecurityLabel(tobject, SEPGSQL_LABEL_TAG);
		sepgsql_audit_log(!!denied,
						  scontext,
						  tcontext,
						  tclass,
						  audited,
						  audit_name);
	}
	if (abort && !result)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("SELinux: security policy violation")));

	return result;
}

char *
sepgsql_client_compute_create(ObjectAddress	   *tobject,
							  security_class_t	tclass)
{
	avc_datum  *cache;

	sepgsql_avc_check_valid();
	do {
		cache = sepgsql_avc_lookup(client_avc_page, tobject, tclass);
		if (!cache)
			cache = sepgsql_avc_make_entry(client_avc_page, tobject, tclass);
	} while (!sepgsql_avc_check_valid());

	return cache->ncontext;
}

/*
 *
 *
 *
 *
 *
 */
void
sepgsql_avc_switch_client(void)
{
	avc_page	   *new_page;
	const char	   *scontext = sepgsql_get_client_label();

	if (client_avc_page)
	{
		new_page = client_avc_page;
		do {
			if (strcmp(new_page->scontext, scontext) == 0)
			{
				client_avc_page = new_page;
				return;
			}
			new_page = new_page->next;
		} while (new_page != client_avc_page);
	}
	/*
	 * not found, so create a new avc_page
	 */
	new_page = MemoryContextAllocZero(avc_mem_cxt,
									  sizeof(avc_page) + strlen(scontext));
	strcpy(new_page->scontext, scontext);

	if (!client_avc_page)
	{
		new_page->next = new_page;
	}
	else
	{
		new_page->next = client_avc_page->next;
		client_avc_page->next = new_page;
	}
	client_avc_page = new_page;
}

/*
 * sepgsql_avc_check_valid
 *
 *
 *
 *
 *
 */
bool
sepgsql_avc_check_valid(void)
{
	if (selinux_state.kernel)
	{
		uint32	seqno;

		while (true)
		{
			__sync_synchronize();

			seqno = selinux_state.kernel->sequence;
			if ((seqno & 0x0001) == 0)
				break;

			sched_yield();
		}
		if (seqno != selinux_state.last_seqno)
		{
			sepgsql_avc_reset();
			selinux_state.last_seqno = seqno;
		}
		return true;
	}
	/*
	 * compatible behavior
	 */
	avc_netlink_check_nb();
	if (selinux_state.last_seqno != selinux_state.curr_seqno)
	{
		sepgsql_avc_reset();
		selinux_state.last_seqno = selinux_state.curr_seqno;
		return false;
	}
	return true;
}

/*
 * sepgsql_avc_getenforce
 *
 * It retrieves the 'enforcing' state of the current policy.
 * Note that the routine shall be enclosed by sepgsql_avc_check_valid()
 */
bool
sepgsql_avc_getenforce(void)
{
	if (selinux_state.kernel != MAP_FAILED)
		return selinux_state.kernel->enforcing;

	return security_getenforce() > 0;
}

/*
 * sepgsql_avc_deny_unknown
 *
 * It retrieves the 'deny_unknown' state of the current policy.
 * Note that the routine shall be enclosed by sepgsql_avc_check_valid()
 */
bool
sepgsql_avc_deny_unknown(void)
{
	if (selinux_state.kernel != MAP_FAILED)
		return selinux_state.kernel->deny_unknown;

	return security_deny_unknown() > 0;
}

/*
 * SELinux kernel status notification
 *
 * If /selinux/status is available, it tries to mmap(2) this file on the
 * selinux_state.kernel. It allows us to read the current kernel status
 * without any system call invocations.
 * In a legacy kernel, it tries to open netlink socket which inform us
 * updates of kernel status.
 */
static int
sepgsql_callback_kernel_status(int value)
{
	/*
	 * it eventually invalidate userspace avc cache.
	 */
	selinux_state.curr_seqno++;

	return 0;
}

static void
sepgsql_open_kernel_status(void)
{
	union selinux_callback cb;
	char	fname[MAXPGPATH];

	memset(&selinux_state, 0, sizeof(selinux_state));

	snprintf(fname, sizeof(fname), "%s/status", selinux_mnt);
	selinux_state.fdesc = open(fname, O_RDONLY);
	if (selinux_state.fdesc < 0)
		goto fallback;

	selinux_state.kernel = mmap(NULL, sysconf(_SC_PAGESIZE),
								PROT_READ, MAP_SHARED,
								selinux_state.fdesc, 0);
	if (selinux_state.kernel == MAP_FAILED)
	{
		close(selinux_state.fdesc);
		goto fallback;
	}
	return;

fallback:
	cb.func_setenforce = sepgsql_callback_kernel_status;
    selinux_set_callback(SELINUX_CB_SETENFORCE, cb);
    cb.func_policyload = sepgsql_callback_kernel_status;
    selinux_set_callback(SELINUX_CB_POLICYLOAD, cb);

	if (avc_netlink_open(0) < 0)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("could not open selinux netlink socket")));

	selinux_state.fdesc = avc_netlink_acquire_fd();

	return;
}

void
sepgsql_avc_init(void)
{
	/*
	 * create local memory context
	 */
	avc_mem_cxt = AllocSetContextCreate(TopMemoryContext,
										"SE-PostgreSQL userspace avc",
										ALLOCSET_DEFAULT_MINSIZE,
										ALLOCSET_DEFAULT_INITSIZE,
										ALLOCSET_DEFAULT_MAXSIZE);
	/*
	 * open kernel event notifier
	 */
	sepgsql_open_kernel_status();

	/*
	 * reset local avc
	 */
	sepgsql_avc_reset();
}
