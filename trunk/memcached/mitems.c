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

#include "memcached/engine.h"
#include "memcached_selinux.h"

static inline uint16_t
mitem_get_keylen(mitem_t *mitem)
{
	return mitem->mchunk->item.keylen;
}

static inline void *
mitem_get_key(mitem_t *mitem)
{
	mchunk_t   *mchunk = mitem->mchunk;


}



static inline void *
mitem_get_data(mitem_t *mitem)
{}


/*
 * mitem object cache
 */
mitem_t *
mitem_cache_lookup(selinux_engine *se,
				   const void *key,
				   const size_t key_len)
{
	mitem_t	   *mitem, *pitem;
	uint32_t	hash;
	int			index;

	hash = se->server->hash(key, key_len, 0);
	index = hash % se->mitem.size;

	for (mitem = se->mitem.slot[index];
		 mitem != NULL;
		 mitem = mitem->next)
	{
		if (mitem->hash == hash &&


			memcmp
		
	}









}










mitem_t *
mitem_allocate(selinux_engine *se,
			   const void *key,
			   const size_t key_len,
			   const size_t data_len,
			   const int flags,
			   const rel_time_t exptime)
{
	mitem_t	   *mitem;
	mchunk_t   *mchunk;
	size_t		length = offset_of(mchunk_t, item.data[0]);

	length += key_len + data_len;
	if (se->config.use_cas)
		length += sizeof(uint64_t);





}

bool
mitem_remove(mhead_t *mhead,
			 mitem_t *mitem)
{}

mitem_t *
mitem_get(mhead_t *mhead,
		  const void *key,
		  const size_t key_len,
	const size_t )
{}

void
mitem_put()
{}

void
miten_get_info(mhead_t *mhead,
			   mitem_t *mitem,
			   item_info *item_info)
{}

/*
 * mitem_init
 *
 *
 */
bool
mitem_init(selinux_engine *se)
{
	mhead_t	   *mhead = se->mhead;
	uint64_t	block_size = mhead->block_size;

	se->mitem.size = (block_size >> (ffsll(block_size) / 2));
	if (se->mitem.size > 0x10000)
		se->mitem.size = 0x10000;
	else if (se->mitem.size < 0x200)
		se->mitem.size = 0x200;

	se->mitem.slot = malloc(sizeof(mitem_t *) * se->mitem.size);
	if (!se->mitem.slot)
		return false;

	memset(se->mitem.slot, 0, sizeof(mitem_t *) * se->mitem.size);
	se->mitem.free_items = NULL;
	se->mitem.num_total = 0;
	se->mitem.num_actives = 0;

	return true;
}
