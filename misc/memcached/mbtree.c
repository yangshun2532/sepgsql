/*
 * mbtree.c
 *
 * mmap based B-plus tree routeines.
 *
 *
 *
 */
#include "memcached/engine.h"
#include "selinux_engine.h"

#define MBTREE_NUM_KEYS		64

typedef struct {
	uint16_t	node;
	uint16_t	flags;
	uint16_t	nkeys;
	uint32_t	keys[MBTREE_NUM_KEYS];
	uint64_t	items[MBTREE_NUM_KEYS + 1];
} mbtree_item;

#define MBTREE_FLAGS_IS_ROOT	0x0001
#define MBTREE_FLAGS_IS_LEAF	0x0002

typedef struct {
	uint64_t	current_leaf;
	uint32_t	current_key;
	uint64_t	current_item;
	int			current_index;	/* items[current_index] == current_item */
} mbtree_state;

/*
 * mbtree_find_index
 *
 * It returns an index of the given mbitem->keys[] array, or mbitem->nkeys.
 * It indexes the least item with key which is equal or larger then the given key.
 */
static int
mbtree_find_index(void *handle, void *mbitem, uint32_t key)
{
	int		min = 0;
	int		max = mbitem->nkeys;
	int		index;

#if 1
	for (index = 0; index < mbitem->nkeys; index++)
	{
		if (keys <= mbitem->nkeys[index])
			break;
	}
	return index;
#endif
	assert(min != max);

	do {
		index = (min + max) / 2;

		if (mbitem->keys[index] < key)
			min = index + 1;
		else
			max = index;
	} while (min != max);

	return min;
}

uint64_t
mbtree_lookup(void *handle, void *mbroot, uint32_t key, mbtree_state *state)
{

	// to be reader lock




	return 0;
}

uint64_t
mbtree_lookup_next(void *handle, void *mbroot, mbtree_state *state)
{

	// to be reader lock


	return 0;
}

bool
mbtree_insert(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_item	   *mbitem = mbroot;
	int				index;
	int				j;

	assert(mbitem->node == NODETAG_MBTREE_ITEM);

	// to be writer lock

	while ((mbitem->flags & MBTREE_FLAGS_IS_LEAF) == 0)
	{
		index = mbtree_find_index(handle, mbitem, key);

		mbitem = offset_to_addr(handle, mbitem[index]);

		assert(mbitem->node == NODETAG_MBTREE_ITEM);
	}

	if (mbitem->nkeys == 0)
	{
		/* a special case when we insert the first item */
		mbitem->keys[0] = key;
		mbitem->items[0] = item;
		mbitem->nkeys++;
	}
	else if (mbitem->nkeys == MBTREE_NUM_KEYS)
	{
		// need to divide it into two

	}
	else
	{
		index = mbtree_find_index(handle, mbitem, key);

		mbitem->items[mbitem->nkeys + 1] = mbitem->items[mbitem->nkeys];
		for (j = mbitem->nkeys; j > index; j--)
		{
			mbitem->keys[j] = mbitem->keys[j - 1];
			mbitem->items[j] = mbitem->keys[j - 1];
		}
		mbitem->keys[index] = key;
		mbitem->items[index] = item;
	}
	return true;
}

bool
mbtree_delete(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_item	   *mbitem = mbroot;
	int				index;
	int				j;

	assert(mbitem->node == NODETAG_MBTREE_ITEM);

	// to be writer lock

	while ((mbitem->flags & MBTREE_FLAGS_IS_LEAF) == 0)
	{
		index = mbtree_find_index(handle, mbitem, key);

		mbitem = offset_to_addr(handle, mbitem[index]);

		assert(mbitem->node == NODETAG_MBTREE_ITEM);
	}

	return true;
}

void *
mbtree_create(void *handle)
{
	mbtree_item	   *mbroot
		= mblock_alloc(handle, sizeof(mbtree_item));

	if (!mbroot)
		return NULL;

	mbroot->node = NODETAG_MBTREE_ITEM;
	mbroot->flags = MBTREE_FLAGS_IS_ROOT | MBTREE_FLAGS_IS_LEAF;
	mbroot->nkeys = 0;
	memset(mbroot->keys, 0, sizeof(mbroot->keys));
	memset(mbroot->items, 0, sizeof(mbroot->items));

	return mbroot;
}
