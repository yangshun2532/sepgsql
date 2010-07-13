/*
 * mitems.c
 *
 * routines to manage item objects
 *
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "selinux_engine.h"

static inline mchunk_t *
mitem_to_mchunk(selinux_engine_t *se, mitem_t *mitem)
{
	int		index = mitem - se->mitems;

	return offset_to_addr(se->mhead, index << MBLOCK_MIN_BITS);
}

static inline mitem_t *
mchunk_to_mitem(selinux_engine_t *se, mchunk_t *mchunk)
{
	uint64_t	offset = addr_to_offset(se->mhead, mchunk);

	return &se->mitems[offset >> MBLOCK_MIN_BITS];
}

static inline void *
mchunk_get_key(mchunk_t *mchunk)
{
	char   *result = (char *)mchunk->item.data;

	if (mchunk->item.flags & MITEM_WITH_CAS)
		result += sizeof(uint64_t);
	return result;
}

static inline void *
mchunk_get_data(mchunk_t *mchunk)
{
	return ((char *)mchunk_get_key(mchunk)) + mchunk->item.keylen;
}

static inline uint64_t
mchunk_get_cas(mchunk_t *mchunk)
{
	if (mchunk->item.flags & MITEM_WITH_CAS)
		return *((uint64_t *) mchunk->item.data);
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
__mchunk_dump(FILE *out, const char *funcname, int lineno,
			  selinux_engine_t *se, uint32_t hkey, uint64_t hitem, mchunk_t *mchunk)
{
	if (mchunk->tag == MCHUNK_TAG_ITEM)
	{
		fprintf(out,
				"%s:%d hkey=0x%08" PRIx32 ", hitem=0x%08" PRIx64 ", "
				"mclass=%d, tag=%d, secid=%" PRIu32 ", "
				"key='%.*s', value='%.*s', "
				"cas=%" PRIu64 ", flags=0x%04x, exptime=%" PRIu32 "\n",
				funcname, lineno, hkey, hitem,
				mchunk->mclass, mchunk->tag, mchunk->item.secid,
				mchunk->item.keylen, (char *)mchunk_get_key(mchunk),
				mchunk->item.datalen - 2, (char *)mchunk_get_data(mchunk),
				mchunk_get_cas(mchunk), mchunk->item.flags, mchunk->item.exptime);
	}
	else
	{
		fprintf(out, "%s:%d "
				"hkey=0x%08" PRIx32 ", hitem=0x%08" PRIx64 ", mclass=%d, tag=%d\n",
				funcname, lineno, hkey, hitem, mchunk->mclass, mchunk->tag);
	}
}

void *
mitem_get_key(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk_get_key(mchunk);
}

size_t
mitem_get_keylen(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->item.keylen;
}

void *
mitem_get_data(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	
	return mchunk_get_data(mchunk);
}

size_t
mitem_get_datalen(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->item.datalen;
}

uint16_t
mitem_get_flags(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->item.flags;
}

uint64_t
mitem_get_cas(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk_get_cas(mchunk);
}

void
mitem_set_cas(selinux_engine_t *se, mitem_t *mitem, uint64_t cas)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	mchunk_set_cas(mchunk, cas);
}

bool
mitem_is_expired(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	uint32_t	exptime = mchunk->item.exptime;
	uint32_t	curtime;

	if (exptime > 0)
	{
		curtime = se->startup_time + se->server.core->get_current_time();

		if (se->config.debug)
			fprintf(stderr, "%s:%d mchunk=%08" PRIx64 ", "
					"exptime=%" PRIu32 ", curtime=%" PRIu32 "\n",
					__FUNCTION__, __LINE__,
					addr_to_offset(se->mhead, mchunk),
					exptime, curtime);

		if (exptime < curtime)
			return true;
	}
	return false;
}

uint32_t
mitem_get_exptime(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	if (mchunk->item.exptime == 0)
		return 0;

	return mchunk->item.exptime - se->startup_time;
}

uint32_t
mitem_get_secid(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	bool		rc;

	if (mchunk->item.secid == 0)
		return 0;

	rc = mlabel_duplicate(se, mchunk->item.secid);
	assert(rc == true);

	return mchunk->item.secid;
}

void
mitem_put_secid(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	bool		rc;

	if (mchunk->item.secid == 0)
		return;

	rc = mlabel_uninstall(se, mchunk->item.secid);
	assert(rc == true);

	return;
}

int
mitem_get_mclass(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->mclass;
}

/*
 * mitem_reclaim
 *
 * NOTE: caller shall hold write-lock
 */
static int
mitem_reclaim(selinux_engine_t *se, size_t required)
{
	mchunk_t	   *mchunk;
	mitem_t		   *mitem;
	mbtree_scan		scan;
	size_t			reclaimed = 0;
	int				count = 0;
	bool			rc;

	required += sizeof(mchunk_t);
	scan.mnode = 0;
	while (reclaimed < required)
	{
		if (!mbtree_lookup(se->mhead, &scan))
		{
			scan.key = 0;
			scan.mnode = 0;
			continue;
		}
		mchunk = offset_to_addr(se->mhead, scan.item);

		if (!mchunk_is_item(mchunk))
			continue;

		/*
		 * No need to reclaim unlinked item
		 */
		if ((mchunk->item.flags & MITEM_LINKED) == 0)
			continue;

		mitem = mchunk_to_mitem(se, mchunk);
		if (mitem->refcnt & MITEM_IS_HOT)
		{
			/* clear hot flag */
			__sync_and_and_fetch(&mitem->refcnt, ~MITEM_IS_HOT);
		}
		else
		{
			size_t	chunk_size = (1 << mchunk->mclass);

			__sync_add_and_fetch(&mitem->refcnt, 2);

			if (se->config.debug)
				mchunk_dump(stderr, se, scan.key, scan.item, mchunk);

			rc = mbtree_delete(se->mhead, scan.key, scan.item);
			assert(rc == true);

			mchunk->item.flags &= ~MITEM_LINKED;

			__sync_add_and_fetch(&se->stats.reclaimed, chunk_size);

			reclaimed += chunk_size;

			mitem_put(se, mitem);

			scan.mnode = 0;
		}
	}
	return count;
}

/*
 * mitem_alloc
 *
 * NOTE: caller shall hold write-lock
 */
mitem_t *
mitem_alloc(selinux_engine_t *se,
			const void *key, size_t key_len, size_t data_len,
			uint32_t secid, int flags, rel_time_t exptime)
{
	mitem_t	   *mitem;
	mchunk_t   *mchunk;
	size_t		length;

	if (se->config.use_cas)
		flags |= MITEM_WITH_CAS;

	length = offset_of(mchunk_t, item.data[0]) + key_len + data_len;
	if ((flags & MITEM_WITH_CAS) != 0)
		length += sizeof(uint64_t);
retry:
	mchunk = mblock_alloc(se->mhead, MCHUNK_TAG_ITEM, length);
	if (!mchunk)
	{
		if (se->config.reclaim)
		{
			mitem_reclaim(se, length);
			goto retry;
		}
		return NULL;
	}
	mitem = mchunk_to_mitem(se, mchunk);
	assert(mitem->refcnt < 2);

	mchunk->item.flags = flags;
	mchunk->item.keylen = key_len;
	mchunk->item.datalen = data_len;
	mchunk->item.secid = secid;
	mchunk->item.exptime = exptime;

	memcpy(mchunk_get_key(mchunk), key, key_len);

	mitem->refcnt = 2 | MITEM_IS_HOT;

	if (se->config.debug)
		mchunk_dump(stderr, se, 0, addr_to_offset(se->mhead, mchunk), mchunk);

	return mitem;
}

/*
 * mitem_link
 *
 * NOTE: caller shall hold write-lock
 */
bool
mitem_link(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	uint32_t	hkey;
	uint64_t	hitem;

	assert((mchunk->item.flags & MITEM_LINKED) == 0);
	assert(mitem->refcnt > 0);

	hkey = se->server.core->hash(mchunk_get_key(mchunk),
								  mchunk->item.keylen, 0);
	hitem = addr_to_offset(se->mhead, mchunk);

	if (se->config.debug)
		mchunk_dump(stderr,se,hkey,hitem,mchunk);

	if (!mbtree_insert(se->mhead, hkey, hitem))
		return false;

	mchunk->item.flags |= MITEM_LINKED;

	return true;
}

/*
 * mitem_unlink
 *
 *
 * NOTE: caller shall hold write-lock
 */
bool
mitem_unlink(selinux_engine_t *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	uint32_t	hkey;
	uint64_t	hitem;

	assert((mchunk->item.flags & MITEM_LINKED) != 0);
	assert(mitem->refcnt > 0);

	hkey = se->server.core->hash(mchunk_get_key(mchunk),
								  mchunk->item.keylen, 0);
	hitem = addr_to_offset(se->mhead, mchunk);

	if (se->config.debug)
		mchunk_dump(stderr,se,hkey,hitem,mchunk);

	if (!mbtree_delete(se->mhead, hkey, hitem))
		return false;

	mchunk->item.flags &= ~MITEM_LINKED;

	return true;
}

/*
 * mitem_get
 *
 * NOTE: caller shall hold read-lock
 */
mitem_t *
mitem_get(selinux_engine_t *se, const void *key, size_t key_len)
{
	mitem_t	   *mitem;
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

		mchunk = offset_to_addr(se->mhead, scan.item);

		if (mchunk_is_item(mchunk) &&
			mchunk->item.keylen == key_len &&
			memcmp(mchunk_get_key(mchunk), key, key_len) == 0)
		{
			if (se->config.debug)
				mchunk_dump(stderr, se, scan.key, scan.item, mchunk);

			mitem = mchunk_to_mitem(se, mchunk);

			__sync_fetch_and_or(&mitem->refcnt, MITEM_IS_HOT);
			__sync_fetch_and_add(&mitem->refcnt, 2);

			return mitem;
		}

		if (se->config.debug)
			fprintf(stderr,
					"%s:%d hkey=0x%08" PRIx32 ", hitem=0x%08" PRIx64 ", mclass=%d tag=%d",
					__FUNCTION__, __LINE__,
					scan.key, scan.item, mchunk->mclass, mchunk->tag);
	}
	/* not found */
	return NULL;
}

/*
 * mitem_put
 *
 * NOTE: caller shall hold read-lock
 */
void
mitem_put(selinux_engine_t *se, mitem_t *mitem)
{
	if (se->config.debug)
		fprintf(stderr, "%s:%d offset=0x%08" PRIx64 " refcnt=%d\n",
				__FUNCTION__, __LINE__,
				addr_to_offset(se->mhead, mitem_to_mchunk(se,mitem)),
				mitem->refcnt);

	if (__sync_sub_and_fetch(&mitem->refcnt, 2) < 2)
	{
		mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

		if ((mchunk->item.flags & MITEM_LINKED) == 0)
			mblock_free(se->mhead, mchunk);
	}
}

/*
 * mitem_flush
 *
 * NOTE: caller shall hold write-lock
 */
void
mitem_flush(selinux_engine_t *se, time_t when)
{
	mchunk_t	   *mchunk;
	mitem_t		   *mitem;
	mbtree_scan		scan;
	rel_time_t		oldest;
	bool			result;

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

		/* instead of mitem_get() */
		mitem = mchunk_to_mitem(se, mchunk);
		__sync_fetch_and_add(&mitem->refcnt, 2);

		result = mbtree_delete(se->mhead, scan.key, scan.item);
		assert(result == true);

		mchunk->item.flags &= ~MITEM_LINKED;

		mitem_put(se, mitem);

		/* B+tree might be modified yet */
		scan.mnode = 0;
	}
}
