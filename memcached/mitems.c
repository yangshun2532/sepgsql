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
mitem_to_mchunk(selinux_engine *se, mitem_t *mitem)
{
	int		index = mitem - se->mitems;

	return offset_to_addr(se->mhead, index << MBLOCK_MIN_BITS);
}

static inline mitem_t *
mchunk_to_mitem(selinux_engine *se, mchunk_t *mchunk)
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

void *
mitem_get_key(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk_get_key(mchunk);
}

size_t
mitem_get_keylen(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->item.keylen;
}

void *
mitem_get_data(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	
	return mchunk_get_data(mchunk);
}

size_t
mitem_get_datalen(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->item.datalen;
}

uint16_t
mitem_get_flags(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->item.flags;
}

uint64_t
mitem_get_cas(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk_get_cas(mchunk);
}

void
mitem_set_flags(selinux_engine *se, mitem_t *mitem, uint16_t flags)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	mchunk->item.flags = flags;
}

void
mitem_set_cas(selinux_engine *se, mitem_t *mitem, uint64_t cas)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	mchunk_set_cas(mchunk, cas);
}

uint32_t
mitem_get_exptime(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->item.exptime;
}

void
mitem_set_exptime(selinux_engine *se, mitem_t *mitem, uint32_t exptime)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	mchunk->item.exptime = exptime;
}

int
mitem_get_mclass(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

	return mchunk->mclass;
}

/*
 * mitem_alloc
 *
 * NOTE: caller shall hold write-lock
 */
mitem_t *
mitem_alloc(selinux_engine *se,
			const void *key, size_t key_len, size_t data_len)
{
	mitem_t	   *mitem;
	mchunk_t   *mchunk;
	size_t		length;
	uint16_t	flags = 0;

	length = offset_of(mchunk_t, item.data[0]) + key_len + data_len;
	if (se->config.use_cas)
	{
		flags |= MITEM_WITH_CAS;
		length += sizeof(uint64_t);
	}

	mchunk = mblock_alloc(se->mhead, MCHUNK_TAG_ITEM, length);
	if (!mchunk)
		return NULL;
	mitem = mchunk_to_mitem(se, mchunk);
	assert(mitem->refcnt == 0);

	mchunk->item.flags = flags;
	mchunk->item.keylen = key_len;
	mchunk->item.datalen = data_len;
	mchunk->item.secid = 0;		/* should be copied from older item */
	mchunk->item.exptime = 0;

	memcpy(mchunk_get_key(mchunk), key, key_len);

	mitem->refcnt = 1;

	return mitem;
}

/*
 * mitem_link
 *
 *
 * NOTE: caller shall hold write-lock
 */
bool
mitem_link(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	uint32_t	hkey;
	uint64_t	hitem;

	assert((mchunk->item.flags & MITEM_LINKED) == 0);
	assert(mitem->refcnt > 0);

	hkey = se->server->core->hash(mchunk_get_key(mchunk),
								  mchunk->item.keylen, 0);
	hitem = addr_to_offset(se->mhead, mchunk);

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
mitem_unlink(selinux_engine *se, mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);
	uint32_t	hkey;
	uint64_t	hitem;

	assert((mchunk->item.flags & MITEM_LINKED) != 0);
	assert(mitem->refcnt > 0);

	hkey = se->server->core->hash(mchunk_get_key(mchunk),
								  mchunk->item.keylen, 0);
	hitem = addr_to_offset(se->mhead, mchunk);

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
mitem_get(selinux_engine *se, const void *key, size_t key_len)
{
	mitem_t	   *mitem;
	mchunk_t   *mchunk;
	uint32_t	hkey;
	mbtree_scan	scan;

	hkey = se->server->core->hash(key, key_len, 0);

	memset(&scan, 0, sizeof(scan));
	while (mbtree_lookup(se->mhead, hkey, &scan))
	{
		mchunk = offset_to_addr(se->mhead, scan.item);

		if (mchunk_is_item(mchunk) &&
			mchunk->item.keylen == key_len &&
			memcmp(mchunk_get_key(mchunk), key, key_len) == 0)
		{
			mitem = mchunk_to_mitem(se, mchunk);

			__sync_fetch_and_add(&mitem->refcnt, 1);

			return mitem;
		}
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
mitem_put(selinux_engine *se, mitem_t *mitem)
{
	if (__sync_sub_and_fetch(&mitem->refcnt, 1) == 0)
	{
		mchunk_t   *mchunk = mitem_to_mchunk(se, mitem);

		if ((mchunk->item.flags & MITEM_LINKED) == 0)
			mblock_free(se->mhead, mchunk);
	}
}
