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
	uint16_t	tag;		/* = TAG_MBTREE_NODE or TAG_MBTREE_LEAF */
	uint16_t	nkeys;		/* # of keys in this node */
	uint64_t	upper;		/* 0, if root node */
	/*
	 * In the case when TAG_MBTREE_NODE
	 * keys[i] (i<n) stores maximum key of the item[i] being either
	 * node or leaf. The items[n] stores offset to node/leaf being
	 * larger than keys[n-1].
	 *
	 * In the case when TAG_MBTREE_LEAF
	 * keys[i] (i<n) stores offset to the items[i] being value of
	 * the corresponding key. key[n] stores offset to the next
	 * leaf, if exist.
	 */
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
mbtree_find_index(void *handle, mbtree_node *mbnode, uint32_t key)
{
	int		min = 0;
	int		max = mbnode->nkeys;
	int		index;

	do {
		index = (min + max) / 2;

		if (mbnode->keys[index] < key)
			min = index + 1;
		else
			max = index;
	} while (min != max);

	return min;
}

static int
mbtree_find_item_index(void *handle, mbtree_node *mbnode, uint64_t item)
{
	int		index;

	for (index=0; index <= mbnode->nkeys; index++)
	{
		if (mbnode->items[index] == item)
			return index;
	}
	return -1;
}

static uint32_t
mbtree_find_min_key(void *handle, mbtree_node *mbnode)
{
	while (!mbnode->leaf)
	{
		mbnode = offset_to_addr(handle, mbnode->items[0]);
		assert(mbnode->tag == TAG_MBTREE_NODE);
	}
	assert(mbnode->tag == TAG_MBTREE_NODE);

	return mbnode->keys[0];
}

static uint32_t
mbtree_find_max_key(void *handle, uint64_t item)
{
	mbtree_node *mnode = offset_to_addr(handle, item);

	while (mnode->tag == TAG_MBTREE_NODE)
		mnode = offset_to_addr(handle, mnode->items[mnode->nkeys]);

	assert(mnode->tag == TAG_MBTREE_LEAF);

	return mnode->keys[mnode->nkeys - 1];
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
				for (j=0; j < index; j++)
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
			mbnode->leaf = false;

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
		mbnode->nkeys++;
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

	assert(mbnode->tag == TAG_MBTREE_NODE);

	// to be writer lock

	while (!mbnode->leaf)
	{
		index = mbtree_find_index(handle, mbnode, key);

		mbnode = offset_to_addr(handle, mbnode[index]);

		assert(mbnode->tag == TAG_MBTREE_NODE);
	}
	return do_mbtree_insert(handle, mbnode, key, item);
}

static void
mbtree_merge(void *handle, mbtree_node *pnode, int index)
{
	mbtree_node	   *lnode = pnode->items[index];
	mbtree_node	   *rnode = pnode->items[index+1];

	assert(lnode->tag == rnode->tag);

	if (lnode->tag == TAG_MBTREE_LEAF)
	{
		if (lnode->nkeys + rnode->nkeys <= MBTREE_NUM_KEYS)
		{
			for (j=0; j < rnode->nkeys; j++)
			{
				lnode->keys[j + lnode->nkeys] = rnode->keys[j];
				lnode->items[j + lnode->nkeys] = rnode->items[j];
			}
			lnode->items[lnode->nkeys + rnode->nkeys] = rnode->items[rnode->nkeys];
			lnode->nkeys += rnode->nkeys;

			for (j=index+1; j < pnode->nkeys; j++)
			{
				pnode->keys[j-1] = pnode->keys[j];
				pnode->items[j-1] = pnode->items[j];
			}
			pnode->nkeys--;
		}
		else if (lnode->nkeys > rnode->nkeys)
		{
			
		}
		else
		{
			
		}
	}
	else
	{
		if (lnode->nkeys + rnode->nkeys < MBTREE_NUM_KEYS)
		{
			lnode->keys[lnode->nkeys]
				= mbtree_find_max_key(handle, lnode->items[lnode->nkeys]);
			lnode->nkeys++;

			for (j=0; j < rnode->nkeys; j++)
			{
				lnode->keys[lnode->nkeys + j] = rnode->keys[j];
				lnode->items[lnode->nkeys + j] = rnode->items[j];
			}
			lnode->nkeys += rnode->nkeys;

			for (j=index+1; j < pnode->nkeys; j++)
			{
				pnode->keys[j-1] = pnode->keys[j];
				pnode->items[j-1] = pnode->items[j];
			}
			pnode->nkeys--;
		}
		else if (lnode->nkeys > rnode->nkeys)
		{
			
		}
		else
		{
			
		}
	}
}

bool
mbtree_delete(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_node	   *pnode = mbroot;
	mbtree_node	   *cnode;
	int				index, j;
	bool			retval;

	if (pnode->tag == TAG_MBTREE_LEAF)
	{
		index = mbtree_find_index(handle, pnode, key);
		while (true)
		{
			if (index == pnode->nkeys)
			{
				if (pnode->items[index] == 0)
					break;

				pnode = offset_to_addr(handle, pnode->items[pnode->nkeys]);
				index = 0;
			}
			if (pnode->keys[index] != key)
				break;
			if (pnode->items[index] == item)
			{
				for (j=index+1; j < pnode->nkeys; j++)
				{
					pnode->keys[j-1] = pnode->keys[j];
					pnode->items[j-1] = pnode->items[j];
				}
				pnode->nkeys--;

				return true;
			}
			index++;
		}
		return false;
	}

	index = mbtree_find_index(handle, pnode, key);
	cnode = offset_to_addr(handle, mbnode->items[index]);

	retval = mbtree_delete(handle, cnode, key, item);
	if (!retval || cnode->nkeys >= MBTREE_NUM_KEYS / 2)
		return retval;

	/*
	 * Merge two nodes, if nkeys are smaller than threshold
	 */
	if (index == mbnode->nkeys)
		index--;
	else if (index > 0)
	{
		mbtree_node *lnode = offset_to_addr(handle, mbnode->items[index - 1]);
		mbtree_node *rnode = offset_to_addr(handle, mbnode->items[index + 1]);
		if (lnode->nkeys < rnode->nkeys)
			index--;
	}
	mbtree_merge(handle, mbnode, index);

	return true;
}

void *
mbtree_create(void *handle)
{
	mbtree_node	   *mbroot = mblock_alloc(handle, sizeof(mbtree_node));

	if (!mbroot)
		return NULL;

	mbroot->tag = TAG_MBTREE_NODE;
	mbroot->nkeys = 0;
	mbroot->upper = 0;
	memset(mbroot->keys, 0, sizeof(mbroot->keys));
	memset(mbroot->items, 0, sizeof(mbroot->items));

	return mbroot;
}

#if 1
int main(int argc, const char *argv[])
{

	return 0;
}
#endif
