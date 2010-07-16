/*
 * mcache.c
 *
 * routines to manage local item/label objects
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "selinux_engine.h"

static inline void *
mchunk_get_key(mchunk_t *mchunk)
{
	char   *result = (char *)mchunk->item.data;

	if (mchunk->item.flags & MITEM_WITH_CAS)
		result += sizeof(uint64_t);
	return (void *)result;
}

static inline size_t
mchunk_get_keylen(mchunk_t *mchunk)
{
	return (size_t)mchunk->item.keylen;
}

static inline void *
mchunk_get_data(mchunk_t *mchunk)
{
	return ((char *)mchunk_get_key(mchunk)) + mchunk_get_keylen(mchunk);
}

static inline size_t
mchunk_get_datalen(mchunk_t *mchunk)
{
	return (size_t)mchunk->item.datalen;
}

static inline uint64_t
mchunk_get_cas(mchunk_t *mchunk)
{
	if (mchunk->item.flags & MITEM_WITH_CAS)
		return *((uint64_t *)mchunk->item.data);
	return 0;
}

static inline void
mchunk_set_cas(mchunk_t *mchunk, uint64_t cas)
{
	if (mchunk->item.flags & MITEM_WITH_CAS)
		*((uint64_t *) mchunk->item.data) = cas;
}

#define mchunk_dump(out,se,hkey,hitem,mchunk)	\
	__mchunk_dump((out),__FUNCTION__,__LINE__,(se),(hkey),(hitem),(mchunk))
static void
__mchunk_dump(FILE *out, const char *fn_name, int lineno,
			  selinux_engine_t *se,
			  uint32_t hkey, uint64_t hitem, mchunk_t *mchunk)
{
	if (mchunk->tag == MCHUNK_TAG_ITEM)
	{
		fprintf(out,
				"%s:%d hkey=0x%08" PRIx32 ", hitem=0x%08" PRIx64 ", "
				"mclass=%d, tag=ITEM, secid=%" PRIu32 ", "
				"key='%.*s', value='%.*s', cas=%" PRIu64 ", flags=0x%04x, "
				"exptime=%" PRIu32 "\n",
				fn_name, lineno, hkey, hitem,
				mchunk->mclass, mchunk->item.secid,
				(int)mchunk_get_keylen(mchunk), (char *)mchunk_get_key(mchunk),
				(int)mchunk_get_datalen(mchunk) - 2, (char *)mchunk_get_data(mchunk),
				mchunk_get_cas(mchunk), mchunk->item.flags, mchunk->item.exptime);
	}
	else if (mchunk->tag == MCHUNK_TAG_LABEL)
	{
		fprintf(out,
				"%s:%d hkey=0x%08" PRIx32 ", hitem=0x%08" PRIx64 ", "
				"mclass=%d, tag=LABEL, secid=%" PRIu32 ", "
				"refcnt=%" PRIu32 ", label='%s'\n",
				fn_name, lineno, hkey, hitem,
				mchunk->mclass, mchunk->label.secid,
				mchunk->label.refcount, mchunk->label.value);
	}
	else
	{
		fprintf(out, "%s:%d "
				"hkey=0x%08" PRIx32 ", hitem=0x%08" PRIx64 ", mclass=%d, tag=%d\n",
				fn_name, lineno, hkey, hitem, mchunk->mclass, mchunk->tag);
    }
}

#define mcache_dump(out,se,mcache)				\
	__mcache_dump((out),__FUNCTION__,__LINE__,(se),(mcache))
static void
__mcache_dump(FILE *out, const char *fnname, int lineno,
			  selinux_engine_t *se, mcache_t *mcache)
{
	mchunk_t   *mchunk = mcache->mchunk;

	fprintf(out,
			"%s:%d mchunk=0x%08" PRIx64 ", refcnt=%d, is_hot=%d, tsid='%s', "
			"mchunk(key='%.*s', value='%.*s', cas=%" PRIu64 ", flags=0x%04x "
			"exptime=%" PRIu32 "\n",
			fnname, lineno,
			addr_to_offset(se->mhead, mchunk),
			mcache->refcnt, mcache->is_hot,
			mcache->tsid ? mcache->tsid->ctx : NULL,
			(int)mchunk_get_keylen(mchunk), (char *)mchunk_get_key(mchunk),
			(int)mchunk_get_datalen(mchunk) - 2, (char *)mchunk_get_data(mchunk),
			mchunk_get_cas(mchunk), mchunk->item.flags, mchunk->item.exptime);
}

void *
mcache_get_key(mcache_t *mcache)
{
	return mchunk_get_key(mcache->mchunk);
}

size_t
mcache_get_keylen(mcache_t *mcache)
{
	return mchunk_get_keylen(mcache->mchunk);
}

void *
mcache_get_data(mcache_t *mcache)
{
	return mchunk_get_data(mcache->mchunk);
}

size_t
mcache_get_datalen(mcache_t *mcache)
{
	return mchunk_get_datalen(mcache->mchunk);
}

uint64_t
mcache_get_cas(mcache_t *mcache)
{
	return mchunk_get_cas(mcache->mchunk);
}

void
mcache_set_cas(mcache_t *mcache, uint64_t cas)
{
	mchunk_set_cas(mcache->mchunk, cas);
}

uint16_t
mcache_get_flags(mcache_t *mcache)
{
	return mcache->mchunk->item.flags;
}

uint32_t
mcache_get_secid(mcache_t *mcache)
{
	return mcache->mchunk->item.secid;
}

int
mcache_get_mclass(mcache_t *mcache)
{
	return mcache->mchunk->mclass;
}

bool
mcache_is_expired(selinux_engine_t *se, mcache_t *mcache)
{
	uint32_t	exptime = mcache->mchunk->item.exptime;
	uint32_t	curtime;

	if (exptime > 0)
	{
		curtime = se->startup_time + se->server.core->get_current_time();

		if (exptime < curtime)
			return true;
	}
	return false;
}

uint32_t
mcache_get_exptime(selinux_engine_t *se, mcache_t *mcache)
{
	mchunk_t   *mchunk = mcache->mchunk;

	if (mchunk->item.exptime == 0)
		return 0;
	return mchunk->item.exptime - se->startup_time;
}

/*
 * declaration of static functions
 */
static mcache_t *mcache_get_internal(selinux_engine_t *se, mchunk_t *mchunk);

static inline int
mcache_index(selinux_engine_t *se, mchunk_t *mchunk)
{
	uint64_t	offset = addr_to_offset(se->mhead, mchunk) >> MBLOCK_MIN_BITS;
	uint32_t	hash = se->server.core->hash(&offset, sizeof(offset), 0x35bd902a);

	return hash % se->mcache.size;
}

/*
 * mcache_reclaim
 *
 * 
 */
static void
mcache_reclaim(selinux_engine_t *se, int num_reclaimed)
{
	mcache_t   *mcache;
	mcache_t   *prev;
	int			index;

	while (num_reclaimed > 0)
	{
		index = __sync_add_and_fetch(&se->mcache.lru_hint, 1) % se->mcache.size;

		pthread_mutex_lock(&se->mcache.locks[index]);

		prev = NULL;
		mcache = se->mcache.slots[index];
		while (mcache)
		{
			if (mcache->is_hot)
				mcache->is_hot = false;
			else if (mcache->refcnt == 0)
			{
				if (!prev)
					se->mcache.slots[index] = mcache->next;
				else
					prev->next = mcache->next;

				pthread_mutex_lock(&se->mcache.free_lock);
				mcache->next = se->mcache.free_list;
				se->mcache.free_list = mcache;
				pthread_mutex_unlock(&se->mcache.free_lock);

				num_reclaimed--;

				continue;
			}
			prev = mcache;
		}
		pthread_mutex_unlock(&se->mcache.locks[index]);
	}
}

/*
 * mitems_reclaim
 *
 * It tries to reclaim expired items
 */
static bool
mitems_reclaim(selinux_engine_t *se, size_t required)
{
	mchunk_t   *mchunk;
	mcache_t   *mcache;
	size_t		reclaimed = 0;
	size_t		chunk_size;
	int			ntries = 150;
	int			count = 0;

	se->scan.mnode = 0;
	while (reclaimed < required && ntries-- > 0)
	{
		if (!mbtree_lookup(se->mhead, &se->scan))
		{
			se->scan.key = 0;
			se->scan.mnode = 0;
			continue;
		}
		mchunk = offset_to_addr(se->mhead, se->scan.item);

		chunk_size = (1 << mchunk->mclass);

		/* Mchunk is not an item (maybe label) */
		if (!mchunk_is_item(mchunk))
			continue;

		/* No need to reclaim unlinked item */
		if ((mchunk->item.flags & MITEM_LINKED) == 0)
			continue;

		mcache = mcache_get_internal(se, mchunk);
		assert(mcache != NULL);

		/* Unlink it, if item is expired */
		if (mcache_is_expired(se, mcache))
		{
			mcache_unlink(se, mcache);
			reclaimed += chunk_size;
			count++;
		}
		mcache_put(se, mcache);
	}
	if (se->config.debug)
		fprintf(stderr, "%s: %d chunks (%u bytes [%u bytes req]) were reclaimed\n",
				__FUNCTION__, count, (uint32_t)reclaimed, (uint32_t)required);

	return (reclaimed < required ? false : true);
}

mcache_t *
mcache_alloc(selinux_engine_t *se,
			 const void *key, size_t key_len, size_t data_len,
			 uint32_t secid, int flags, rel_time_t exptime)
{
	mcache_t	   *mcache;
	mchunk_t	   *mchunk;
	mchunk_t	   *lchunk = NULL;
	size_t			length;
	security_id_t	tsid = NULL;
	int				index;

	assert((flags & MITEM_LINKED) == 0);
	if (se->config.use_cas)
		flags |= MITEM_WITH_CAS;

	length = offset_of(mchunk_t, item.data[0]) + key_len + data_len;
	if ((flags & MITEM_WITH_CAS) != 0)
		length += sizeof(uint64_t);
	/*
	 * security label validation
	 */
	if (secid > 0)
	{
		lchunk = mlabel_lookup_secid(se, secid);
		if (!lchunk)
			secid = 0;
		else
			lchunk->label.refcount++;
	}

	if (se->config.selinux)
	{
		if (!lchunk)
		{
			if (avc_get_initial_sid("unlabeled", &tsid) < 0)
				return NULL;
		}
		else
		{
			if (avc_context_to_sid_raw(lchunk->label.value, &tsid) < 0)
			{
				lchunk->label.refcount--;
				return NULL;
			}
		}
	}

	/*
	 * allocate from memory block
	 */
retry_1:
	mchunk = mblock_alloc(se->mhead, MCHUNK_TAG_ITEM, length);
	if (!mchunk)
	{
		if (se->config.reclaim && mitems_reclaim(se, length))
			goto retry_1;

		return NULL;
	}
	mchunk->item.flags = flags;
	mchunk->item.exptime = exptime + se->startup_time;
	mchunk->item.secid = secid;
	mchunk->item.keylen = key_len;
	mchunk->item.datalen = data_len;
	memcpy(mchunk_get_key(mchunk), key, key_len);
	memset(mchunk_get_data(mchunk), 0, data_len);

	/*
	 * allocate a mcache entry
	 */
retry_2:
	pthread_mutex_lock(&se->mcache.free_lock);

	mcache = se->mcache.free_list;
	if (!mcache)
	{
		pthread_mutex_unlock(&se->mcache.free_lock);
		mcache_reclaim(se, 10);
		goto retry_2;
	}
	se->mcache.free_list = mcache->next;
	pthread_mutex_unlock(&se->mcache.free_lock);

	mcache->refcnt = 1;
	mcache->is_hot = true;
	mcache->tsid = tsid;
	mcache->mchunk = mchunk;

	index = mcache_index(se, mchunk);

	pthread_mutex_lock(&se->mcache.locks[index]);

	mcache->next = se->mcache.slots[index];
	se->mcache.slots[index] = mcache;

	pthread_mutex_unlock(&se->mcache.locks[index]);

	if (se->config.debug)
		mcache_dump(stderr, se, mcache);

	return mcache;
}

/*
 * mcache_link
 *
 * MEMO: caller must hold write-lock
 */
bool
mcache_link(selinux_engine_t *se, mcache_t *mcache)
{
	uint32_t	hkey;
	uint64_t	hitem;

	assert((mcache->mchunk->item.flags & MITEM_LINKED) == 0);
	assert(mcache->refcnt > 0);

	hkey = se->server.core->hash(mcache_get_key(mcache),
								 mcache_get_keylen(mcache), 0);
	hitem = addr_to_offset(se->mhead, mcache->mchunk);

	if (!mbtree_insert(se->mhead, hkey, hitem))
		return false;

	mcache->mchunk->item.flags |= MITEM_LINKED;

	if (se->config.debug)
		mcache_dump(stderr, se, mcache);

	return true;
}

/*
 * mcache_unlink
 *
 * MEMO: caller must hold write-lock
 */
bool
mcache_unlink(selinux_engine_t *se, mcache_t *mcache)
{
	uint32_t	hkey;
	uint64_t	hitem;

	assert((mcache->mchunk->item.flags & MITEM_LINKED) != 0);
	assert(mcache->refcnt > 0);

	hkey = se->server.core->hash(mcache_get_key(mcache),
								 mcache_get_keylen(mcache), 0);
	hitem = addr_to_offset(se->mhead, mcache->mchunk);

	if (!mbtree_delete(se->mhead, hkey, hitem))
		return false;

	mcache->mchunk->item.flags &= ~MITEM_LINKED;

	if (se->config.debug)
		mcache_dump(stderr, se, mcache);

	return true;
}

/*
 * mcache_get
 *
 * MEMO: caller must hold read-lock, at least
 */
static mcache_t *
mcache_get_internal(selinux_engine_t *se, mchunk_t *mchunk)
{
	mcache_t	   *mcache;
	mchunk_t	   *lchunk = NULL;
	security_id_t	tsid = NULL;
	int				index = mcache_index(se, mchunk);
	int				rc;

retry:
	pthread_mutex_lock(&se->mcache.locks[index]);

	for (mcache = se->mcache.slots[index]; mcache; mcache = mcache->next)
	{
		if (mcache->mchunk == mchunk)
		{
			mcache->is_hot = true;
			mcache->refcnt++;

			pthread_mutex_unlock(&se->mcache.locks[index]);

			return mcache;
		}
	}

	/*
	 * If no available mcache, a new cache will be inserted
	 */
	pthread_mutex_lock(&se->mcache.free_lock);
	if (se->mcache.free_list == NULL)
	{
		pthread_mutex_unlock(&se->mcache.free_lock);
		pthread_mutex_unlock(&se->mcache.locks[index]);

		mcache_reclaim(se, 10);

		goto retry;
	}
	mcache = se->mcache.free_list;
	se->mcache.free_list = mcache->next;

	pthread_mutex_unlock(&se->mcache.free_lock);

	/* set up mcache */
	mcache->refcnt = 1;
	mcache->is_hot = true;
	if (se->config.selinux)
	{
		if (mchunk->item.secid > 0)
			lchunk = mlabel_lookup_secid(se, mchunk->item.secid);

		if (!lchunk)
			rc = avc_get_initial_sid("unlabeled", &tsid);
		else
			rc = avc_context_to_sid_raw(lchunk->label.value, &tsid);

		if (rc < 0)
		{
			pthread_mutex_lock(&se->mcache.free_lock);
			mcache->next = se->mcache.free_list;
			se->mcache.free_list = mcache;
			pthread_mutex_unlock(&se->mcache.free_lock);

			return NULL;
		}
	}
	mcache->tsid = tsid;
	mcache->mchunk = mchunk;

	mcache->next = se->mcache.slots[index];
	se->mcache.slots[index] = mcache;

	__sync_add_and_fetch(&se->mcache.num_actives, 1);

	pthread_mutex_unlock(&se->mcache.locks[index]);

	return mcache;
}

mcache_t *
mcache_get(selinux_engine_t *se, const void *key, size_t key_len)
{
	mcache_t   *mcache;
	mchunk_t   *mchunk;
	uint32_t	hkey;
	mbtree_scan	scan;

	hkey = se->server.core->hash(key, key_len, 0);

	memset(&scan, 0, sizeof(scan));
	scan.key = hkey;
	while (mbtree_lookup(se->mhead, &scan))
	{
		if (scan.key != hkey)
			break;

		/* verify correctness of the mchunk */
		mchunk = offset_to_addr(se->mhead, scan.item);
		if (!mchunk_is_item(mchunk) ||
			mchunk->item.keylen != key_len ||
			memcmp(mchunk_get_key(mchunk), key, key_len) != 0)
			continue;

		mcache = mcache_get_internal(se, mchunk);
		if (mcache && se->config.debug)
			mcache_dump(stderr, se, mcache);

		return mcache;
	}
	/* Not found */
	return NULL;
}

/*
 * mcache_put
 *
 * MEMO: caller must hold read-lock, but write-lock when mcache->is_linked
 *       is not true
 */
void
mcache_put(selinux_engine_t *se, mcache_t *mcache)
{
	int		index = mcache_index(se, mcache->mchunk);

	if (se->config.debug)
		mcache_dump(stderr, se, mcache);

	pthread_mutex_lock(&se->mcache.locks[index]);
	if (--mcache->refcnt == 0)
	{
		if ((mcache->mchunk->item.flags & MITEM_LINKED) == 0)
		{
			mcache_t   *prev = NULL;

			/*
			 * Release Memory Block
			 */
			if (mcache->mchunk->item.secid != 0)
				mlabel_put(se, mcache->mchunk->item.secid);
			mblock_free(se->mhead, mcache->mchunk);

			/*
			 * Also release from mcache hash
			 */
			if (mcache == se->mcache.slots[index])
				se->mcache.slots[index] = mcache->next;
			else
			{
				for (prev = se->mcache.slots[index];
					 prev && prev->next != mcache;
					 prev = prev->next);
				assert(prev != NULL);

				prev->next = mcache->next;
			}
			pthread_mutex_lock(&se->mcache.free_lock);

			mcache->next = se->mcache.free_list;
			se->mcache.free_list = mcache;

			pthread_mutex_unlock(&se->mcache.free_lock);
		}
	}
	pthread_mutex_unlock(&se->mcache.locks[index]);
}

void
mcache_flush(selinux_engine_t *se, time_t when)
{
	mchunk_t	   *mchunk;
	mcache_t	   *mcache;
	mbtree_scan		scan;
	rel_time_t		oldest;

	if (when == 0)
		oldest = se->server.core->get_current_time() + se->startup_time - 1;
	else
		oldest = se->startup_time + when - 1;

	memset(&scan, 0, sizeof(scan));
	while (mbtree_lookup(se->mhead, &scan))
	{
		mchunk = offset_to_addr(se->mhead, scan.item);

		if (!mchunk_is_item(mchunk))
			continue;
		if (mchunk->item.exptime >= oldest)
			continue;

		assert((mchunk->item.flags & MITEM_LINKED) != 0);

		if (se->config.debug)
			mchunk_dump(stderr, se, scan.key, scan.item, mchunk);

		mcache = mcache_get_internal(se, mchunk);

		mcache_unlink(se, mcache);

		mcache_put(se, mcache);

		scan.mnode = 0;
	}
}

bool
mcache_init(selinux_engine_t *se)
{
	uint64_t	block_size = se->config.block_size;
	mcache_t   *mcache;
	int			i;

	se->mcache.size = (block_size >> (ffsll(block_size) / 2));
	if (se->mcache.size > 0x40000)
		se->mcache.size = 0x40000;
	else if (se->mcache.size < 0x400)
		se->mcache.size = 0x400;

	se->mcache.locks = malloc(sizeof(pthread_mutex_t) * se->mcache.size);
	if (!se->mcache.locks)
		return false;

	se->mcache.slots = malloc(sizeof(mcache_t *) * se->mcache.size);
	if (!se->mcache.slots)
	{
		free(se->mcache.locks);
		return false;
	}

	for (i=0; i < se->mcache.size; i++)
	{
		pthread_mutex_init(&se->mcache.locks[i], NULL);
		se->mcache.slots[i] = NULL;
	}
	pthread_mutex_init(&se->mcache.free_lock, NULL);
	se->mcache.free_list = NULL;
	se->mcache.lru_hint = 0;

	/* allocate free mcaches */
	for (i=0; i < se->mcache.size; i++)
	{
		mcache = malloc(sizeof(mcache_t));
		if (!mcache)
		{
			mcache_t   *next;

			for (mcache = se->mcache.free_list; mcache; mcache = next)
			{
				next = mcache->next;
				free(mcache);
			}
			return false;
		}
		mcache->next = se->mcache.free_list;
		se->mcache.free_list = mcache;
	}
	return true;
}

/*
 * mlabel_lookup_secid
 *
 * NOTE: caller must hold reader-lock at least
 */
mchunk_t *
mlabel_lookup_secid(selinux_engine_t *se, uint32_t secid)
{
	mbtree_scan		scan;
	mchunk_t	   *mchunk;

	memset(&scan, 0, sizeof(scan));
	scan.key = secid;
	while (mbtree_lookup(se->mhead, &scan) && scan.key == secid)
	{
		mchunk = offset_to_addr(se->mhead, scan.item);
		if (mchunk_is_label(mchunk) &&
			mchunk->label.secid == secid)
		{
			if (se->config.debug)
				fprintf(stderr, "%s: security label '%s' (secid=%u)\n",
						__FUNCTION__, mchunk->label.value, secid);
			return mchunk;
		}
	}
	if (se->config.debug)
		fprintf(stderr, "%s: no valid security label (secid=%u)\n",
				__FUNCTION__, secid);

	return NULL;
}

/*
 * mlabel_lookup_label
 *
 * NOTE: caller must hold reader-lock at least
 */
mchunk_t *
mlabel_lookup_label(selinux_engine_t *se, const char *label)
{
	mbtree_scan		scan;
	mchunk_t	   *mchunk;
	uint32_t		hkey;

	hkey = se->server.core->hash(label, strlen(label), 0);

	memset(&scan, 0, sizeof(scan));
	scan.key = hkey;
	while (mbtree_lookup(se->mhead, &scan) && scan.key == hkey)
	{
		mchunk = offset_to_addr(se->mhead, scan.item);
		if (mchunk_is_label(mchunk) &&
			strcmp(mchunk->label.value, label) == 0)
		{
			if (se->config.debug)
				fprintf(stderr, "%s: security label '%s' (secid=%u)\n",
						__FUNCTION__, label, mchunk->label.secid);
			return mchunk;
		}
	}
	if (se->config.debug)
		fprintf(stderr, "%s: no valid security label (label='%s')\n",
				__FUNCTION__, label);

	return NULL;
}

static uint32_t
assign_new_secid(selinux_engine_t *se)
{
	mbtree_scan		scan;
	mchunk_t	   *mchunk;
	uint32_t		secid;

	secid = se->mhead->last_secid + 1;
	memset(&scan, 0, sizeof(scan));
	scan.key = secid;
	while (mbtree_lookup(se->mhead, &scan))
	{
		if (scan.key != secid)
			break;

		mchunk = offset_to_addr(se->mhead, scan.item);
		if (!mchunk_is_label(mchunk))
			break;

		if (++secid == 0)
			secid = 1;
		scan.key = secid;
	}
	se->mhead->last_secid = secid;

	return secid;
}

/*
 * mlabel_get
 *
 * NOTE: caller must hold write-lock
 */
uint32_t
mlabel_get(selinux_engine_t *se, const char *label)
{
	mchunk_t   *mchunk;
	uint32_t	hkey;
	uint32_t	hitem;
	size_t		length;

	mchunk = mlabel_lookup_label(se, label);
	if (mchunk)
	{
		mchunk->label.refcount++;

		return mchunk->label.secid;
	}
	length = offset_of(mchunk_t, label.value[1]) + strlen(label);
retry:
	mchunk = mblock_alloc(se->mhead, MCHUNK_TAG_LABEL, length);
	if (!mchunk)
	{
		if (se->config.reclaim && mitems_reclaim(se, length))
			goto retry;
		return 0;
	}
	mchunk->label.secid = assign_new_secid(se);
	mchunk->label.refcount = 1;
	strcpy(mchunk->label.value, label);

	hkey = se->server.core->hash(label, strlen(label), 0);
	hitem = addr_to_offset(se->mhead, mchunk);

	if (!mbtree_insert(se->mhead, hkey, hitem))
	{
		mblock_free(se->mhead, mchunk);
		return 0;
	}
	if (!mbtree_insert(se->mhead, mchunk->label.secid, hitem))
	{
		mbtree_delete(se->mhead, hkey, hitem);
		mblock_free(se->mhead, mchunk);
		return 0;
	}
	return mchunk->label.secid;
}

bool
mlabel_put(selinux_engine_t *se, uint32_t secid)
{
	mchunk_t   *mchunk;
	uint32_t	hkey;
	uint64_t	hitem;
	bool		rc;

	mchunk = mlabel_lookup_secid(se, secid);
	if (!mchunk)
	{
		if (se->config.debug)
			fprintf(stderr, "%s:%d no label entry for secid=%u\n",
					__FUNCTION__, __LINE__, secid);
		return false;
	}

	if (--mchunk->label.refcount == 0)
	{
		hkey = se->server.core->hash(mchunk->label.value,
									 strlen(mchunk->label.value), 0);
		hitem = addr_to_offset(se->mhead, mchunk);

		/* remove from index */
		rc = mbtree_delete(se->mhead, secid, hitem);
		assert(rc == true);

		rc = mbtree_delete(se->mhead, hkey,  hitem);
		assert(rc == true);

		/* release its mchunk */
		mblock_free(se->mhead, mchunk);
	}
	return true;
}
