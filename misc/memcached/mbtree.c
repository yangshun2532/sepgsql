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

#define MBTREE_NUM_KEYS		8

typedef struct {
	uint8_t		tag;		/* = TAG_MBTREE_NODE */
	uint8_t		leaf;		/* true, if leaf node */
	uint16_t	nkeys;		/* # of keys in this node */
	uint64_t	upper;		/* 0, if root node */
	uint32_t	keys[MBTREE_NUM_KEYS];
	uint64_t	items[MBTREE_NUM_KEYS + 1];
} mbtree_node;

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

static bool
do_mbtree_insert(void *handle, mbtree_node *mbnode, uint32_t key, uint64_t item)
{
	mbtree_node	   *pnode;
	mbtree_node	   *lnode;
	mbtree_node	   *rnode;
	int				index, j;

	if (mbnode->nkeys == MBTREE_NUM_KEYS)
	{
		if (mbnode->upper == 0)
		{
			lnode = mblock_alloc(handle, sizeof(mbtree_node));
			if (!lnode)
				return false;

			rnode = mblock_alloc(handle, sizeof(mbtree_node));
			if (!rnode)
			{
				mblock_free(lnode);
				return false;
			}

			lnode->tag = TAG_MBTREE_NODE;
			rnode->tag = TAG_MBTREE_NODE;

			lnode->leaf = mbnode->leaf;
			rnode->leaf = mbnode->leaf;

			lnode->upper = addr_to_offset(handle, mbnode);
			rnode->upper = addr_to_offset(handle, mbnode);

			index = mbnode->nkeys / 2;
			if (mbnode->leaf)
			{
				for (j=0; j < i; j++)
				{
					lnode->keys[j] = mbnode->keys[j];
					lnode->items[j] = mbnode->items[j];
				}
				for (j=index; j < mbnode->nkeys; j++)
				{
					rnode->keys[j-index] = mbnode->keys[j];
					rnode->items[j-index] = mbnode->items[j];
				}
				lnode->items[index] = addr_to_offset(handle, rnode);
				rnode->items[mbnode->nkeys - index] = mbnode->items[mbnode->nkeys];

				lnode->nkeys = index;
				rnode->nkeys = mbnode->nkeys - index;
			}
			else
			{
				for (j=0; j < index; j++)
				{
					lnode->keys[j] = mbnode->keys[j];
					lnode->items[j] = mbnode->items[j];
				}
				for (j=index+1; j < mbnode->nkeys; j++)
				{
					rnode->keys[j - (index+1)] = mbnode->keys[j];
					rnode->items[j - (index+1)] = mbnode->items[j];
				}
				lnode->item[index] = mbnode->items[index];
				rnode->item[mbnode->nkeys - (index+1)] = mbnode->item[mbnode->nkeys];

				lnode->nkeys = index;
				rnode->nkeys = mbnode->nkeys - (index+1);
			}

			mbnode->nkeys = 1;
			mbnode->keys[0] = rnode->keys[0];
			mbnode->items[0] = addr_to_offset(handle, lnode);
			mbnode->items[1] = addr_to_offset(handle, rnode);
			mbnode->flags &= ~MBTREE_FLAGS_LEAF;

			if (key <= mbnode->keys[0])
				do_mbtree_insert(handle, lnode, key, item);
			else
				do_mbtree_insert(handle, rnode, key, item);
		}
		else
		{
			rnode = mblock_alloc(handle, sizeof(mbtree_node));
			if (!rnode)
				return false;
			pnode = offset_to_addr(handle, mbnode->upper);

			index = mbnode->nkeys / 2;
			if (!do_mbtree_insert(handle, pnode,
								  mbnode->keys[index],
								  addr_to_offset(handle, rnode)))
			{
				mblock_free(handle, rnode);
				return false;
			}

			rnode->tag = TAG_MBTREE_NODE;
			rnode->flags = mbnode->flags;

			if (mbnode->leaf)
			{
				for (j=i; j < mbnode->nkeys; j++)
				{
					rnode->keys[j-index] = mbnode->keys[j];
					rnode->items[j-index] = mbnode->items[j];
				}
				mbnode->items[index] = addr_to_offset(handle, rnode);
				rnode->nkeys = mbnode->nkeys - index;
			}
			else
			{
				for (j=index+1; j < mbnode->nkeys; j++)
				{
					rnode->keys[j-(index+1)] = mbnode->keys[j];
					rnode->items[j-(index+1)] = mbnode->items[j];
				}
				rnode->nkeys = mbnode->nkeys-(index+1);
			}
			rnode->items[mbnode->nkeys - index] = mbnode->items[mbnode->nkeys];
			mbnode->nkeys = index;
		}
	}
	else
	{
		i = mbtree_find_index(handle, mbnode, key);

		mbnode->items[mbnode->nkeys + 1] = mbnode->items[mbnode->nkeys];
		for (j = mbnode->nkeys; j > i; j--)
		{
			mbnode->keys[j] = mbnode->keys[j - 1];
			mbnode->items[j] = mbnode->items[j - 1];
		}
		mbnode->keys[i] = key;
		mbnode->items[i] = item;
	}
	return true;
}


bool
mbtree_insert(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_node	   *mbnode = mbroot;
	mbtree_node	   *mbparent;
	int				index;
	int				j;

	assert(mbnode->tag == TAG_MBTREE_NODE);

	// to be writer lock

	while ((mbnode->flags & MBTREE_FLAGS_LEAF) == 0)
	{
		index = mbtree_find_index(handle, mbnode, key);

		mbitem = offset_to_addr(handle, mbitem[index]);

		assert(mbnode->tag == TAG_MBTREE_NODE);
	}

	return do_mbtree_insert(handle, mbnode, key, item);
}

bool
mbtree_delete(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_node	   *mbnode = mbroot;
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
	mbtree_node	   *mbroot = mblock_alloc(handle, sizeof(mbtree_node));

	if (!mbroot)
		return NULL;

	mbroot->tag = TAG_MBTREE_NODE;
	mbroot->flags = MBTREE_FLAGS_ROOT | MBTREE_FLAGS_LEAF;
	mbroot->nkeys = 0;
	mbroot->upper = 0;
	memset(mbroot->keys, 0, sizeof(mbroot->keys));
	memset(mbroot->items, 0, sizeof(mbroot->items));

	return mbroot;
}
