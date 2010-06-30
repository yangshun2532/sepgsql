/*
 * mbtree.c
 *
 * mmap based B-plus tree routeines.
 *
 *
 *
 */
#include <assert.h>
#include <string.h>

#include "memcached/engine.h"
#include "selinux_engine.h"

#define MBTREE_NUM_KEYS		6	/* optimal size for 128B chunk */

#define TAG_MBTREE_NODE			0x01
#define TAG_MBTREE_LEAF			0x02

/*
 * A superblock structure of the mmap based B+ tree 
 */
typedef struct
{
	uint64_t	root;		/* offset of the root node */
} mbtree_super;

/*
 * Node structure of the B+ tree
 */
typedef struct
{
	uint16_t	tag;		/* TAG_MBTREE_NODE or TAG_MBTREE_LEAF */
	uint16_t	nkeys;		/* # of keys in this node */
	uint64_t	upper;		/* offset of the parent node */
	/*
	 * In the case when TAG_MBTREE_NODE
	 * key[i] (i<n) = max(items[i])
	 *   and all the keys of item[n] are larger than key[n-1]
	 *
	 * In the case when TAG_MBTREE_LEAF
	 * key[i] (i<n) = key of the item[i]
	 *   and items[MBTREE_NUM_KEYS] is offset to the next node
	 */
	uint32_t	keys[MBTREE_NUM_KEYS];
	uint64_t	items[MBTREE_NUM_KEYS + 1];
} mbtree_node;

/*
 * find_key_index
 *
 * It returns the index of a certain mbtree_node. The indexed key
 * is equal or least which over the given key.
 * (it never lower than the given key.)
 */
static int
find_key_index(mbtree_node *mnode, uint32_t key)
{
	int		min = 0;
	int		max = mnode->nkeys;
	int		index;

	if (mnode->nkeys == 0)
	{
		assert(mnode->upper == 0);
		return 0;
	}

	do {
		index = (min + max) / 2;

		if (mnode->keys[index] < key)
			min = index + 1;
		else
			max = index;
	} while (min != max);

	return min;
}

/*
 * find_item_index
 *
 * It returns the index which stores a certain child-node.
 */
static int
find_item_index(mbtree_super *mbsup, mbtree_node *pnode, mbtree_node *cnode)
{
	uint64_t	item = mblock_addr_to_offset(mbsup, cnode);
	int			index;

	assert(pnode->tag == TAG_MBTREE_NODE);
	for (index=0; index <= pnode->nkeys; index++)
	{
		if (pnode->items[index] == item)
			return index;
	}
	assert(false);
}

static void
children_reparent(mbtree_super *mbsup, mbtree_node *mnode, mbtree_node *pnode)
{
	uint64_t	new_upper = mblock_addr_to_offset(mbsup, pnode);
	int			index;

	for (index = 0; index <= mnode->nkeys; index++)
	{
		mbtree_node *cnode = mblock_offset_to_addr(mbsup, mnode->items[index]);

		cnode->upper = new_upper;
	}
}

/*
 * mbtree_lookup
 *
 * It returns the item which matches with the given key.
 */
bool
mbtree_lookup(void *handle, uint32_t key, mbtree_scan *scan)
{
	mbtree_super   *mbsup = handle;
	mbtree_node	   *mnode; // = mblock_offset_to_addr(mbsup, mbsup->root);
	int				index;

	if (scan->mnode == 0 || scan->key != key)
	{
		/*
		 * If mbtree_scan is not under scanning, we try to
		 * look up B+ tree from the root node.
		 */
		mnode = mblock_offset_to_addr(mbsup, mbsup->root);

		while (mnode->tag == TAG_MBTREE_NODE)
		{
			index = find_key_index(mnode, key);

			mnode = mblock_offset_to_addr(mbsup, mnode->items[index]);
		}
		index = find_key_index(mnode, key);
		if (mnode->keys[index] == key)
		{
			scan->mnode = mblock_addr_to_offset(mbsup, mnode);
			scan->index = index;
			scan->key = key;
			scan->item = mnode->items[index];

			return true;
		}
	}
	else
	{
		/*
		 * If mbtree_scan is under scanning with a certain key,
		 * we try to fetch the next item. If its key is not
		 * matched, it returns false.
		 */
		mnode = mblock_offset_to_addr(mbsup, scan->mnode);
		index = scan->index + 1;

		if (mnode->nkeys == index)
		{
			mnode = mblock_offset_to_addr(mbsup, mnode->items[index]);
			index = 0;
		}
		if (mnode->keys[index] == scan->key)
		{
			scan->mnode = mblock_addr_to_offset(mbsup, mnode);
			scan->index = index;
			scan->item = mnode->items[index];

			return true;
		}
	}
	return false;
}

/*
 * mbtree_dump
 *
 * print debug info
 */
static void
mbtree_dump_node(mbtree_super *mbsup, mbtree_node *mnode, int nestlv)
{
	mbtree_node	   *cnode;
	int				i;

	if (mnode->tag == TAG_MBTREE_LEAF)
	{
		printf("%*sleaf(0x%" PRIx64 ", nkeys=%d, upper=0x%" PRIx64 ") {\n", nestlv, "",
			   mblock_addr_to_offset(mbsup, mnode), mnode->nkeys, mnode->upper);
		for (i=0; i < mnode->nkeys; i++)
			printf("%*skey=%" PRIu32 ", value=%" PRIu64 "\n", nestlv + 2, "",
				   mnode->keys[i], mnode->items[i]);
		printf("%*s} next=0x%" PRIx64 "\n", nestlv, "",
			   mnode->items[mnode->nkeys]);
	}
	else
	{
		printf("%*snode(0x%" PRIx64 ", nkeys=%d, upper=0x%" PRIx64 ") {\n", nestlv, "",
			   mblock_addr_to_offset(mbsup, mnode), mnode->nkeys, mnode->upper);
		for (i=0; i <= mnode->nkeys; i++)
		{
			cnode = mblock_offset_to_addr(mbsup, mnode->items[i]);
			mbtree_dump_node(mbsup, cnode, nestlv+2);

			if (i < mnode->nkeys)
				printf("%*s* key=%" PRIu32 "\n", nestlv + 2, "", mnode->keys[i]);
		}
		printf("%*s}\n", nestlv, "");
	}
}

void
mbtree_dump(void *handle)
{
	mbtree_super   *mbsup = handle;
	mbtree_node	   *mnode = mblock_offset_to_addr(mbsup, mbsup->root);

	mbtree_dump_node(mbsup, mnode, 0);
}

/*
 * mbtree_divide
 *
 * divide a certain node into two nodes.
 */
static bool
mbtree_divide(mbtree_super *mbsup, mbtree_node *mnode)
{
	assert(mnode->nkeys == MBTREE_NUM_KEYS);

	if (!mnode->upper)
	{
		mbtree_node	   *lnode;
		mbtree_node	   *rnode;
		uint32_t		pkey;
		int				xsect;

		lnode = mblock_alloc(mbsup, sizeof(mbtree_node));
		if (!lnode)
			return false;

		rnode = mblock_alloc(mbsup, sizeof(mbtree_node));
		if (!rnode)
		{
			mblock_free(mbsup, lnode);
			return false;
		}

		lnode->tag = rnode->tag = mnode->tag;
		lnode->upper = rnode->upper = mblock_addr_to_offset(mbsup, mnode);

		xsect = mnode->nkeys / 2;
		if (mnode->tag == TAG_MBTREE_LEAF)
		{
			/* copy smaller half to lnode */
			memcpy(lnode->keys, mnode->keys,
				   sizeof(uint32_t) * xsect);
			memcpy(lnode->items, mnode->items,
				   sizeof(uint64_t) * xsect);
			lnode->nkeys = xsect;
			lnode->items[lnode->nkeys] = mblock_addr_to_offset(mbsup, rnode);

			/* copy larger half to rnode */
			memcpy(rnode->keys, mnode->keys + xsect,
				   sizeof(uint32_t) * (mnode->nkeys - xsect));
			memcpy(rnode->items, mnode->items + xsect,
				   sizeof(uint64_t) * (mnode->nkeys - xsect));
			rnode->nkeys = mnode->nkeys - xsect;
			rnode->items[rnode->nkeys] = 0;

			pkey = lnode->keys[lnode->nkeys - 1];
		}
		else
		{
			/* copy smaller half to lnode */
			memcpy(lnode->keys, mnode->keys,
				   sizeof(uint32_t) * xsect);
			memcpy(lnode->items, mnode->items,
				   sizeof(uint64_t) * (xsect + 1));
			lnode->nkeys = xsect;
			children_reparent(mbsup, lnode, lnode);

			/* copy larger half to rnode */
			memcpy(rnode->keys, mnode->keys + xsect + 1,
				   sizeof(uint32_t) * (mnode->nkeys - xsect - 1));
			memcpy(rnode->items, mnode->items + xsect + 1,
				   sizeof(uint64_t) * (mnode->nkeys - xsect));
			rnode->nkeys = mnode->nkeys - xsect - 1;
			children_reparent(mbsup, rnode, rnode);
			pkey = mnode->keys[xsect];
		}
		/* set up root node */
		mnode->tag = TAG_MBTREE_NODE;
		mnode->nkeys = 1;
		mnode->keys[0] = pkey;
		mnode->items[0] = mblock_addr_to_offset(mbsup, lnode);
		mnode->items[1] = mblock_addr_to_offset(mbsup, rnode);
	}
	else
	{
		mbtree_node	   *pnode;
		mbtree_node	   *nnode;
		uint32_t		pkey;
		int				xsect, index;

		/*
		 * In the case when non-root node, we need to make sure
		 * the parent node has a slot to store the new node at
		 * least. If the parent is also full, we recursively
		 * divide the root node.
		 * Note that @mnode might be reparented during the divide.
		 */
		pnode = mblock_offset_to_addr(mbsup, mnode->upper);
		if (pnode->nkeys == MBTREE_NUM_KEYS)
		{
			if (!mbtree_divide(mbsup, pnode))
				return false;
			pnode = mblock_offset_to_addr(mbsup, mnode->upper);
		}

		nnode = mblock_alloc(mbsup, sizeof(mbtree_node));
		if (!nnode)
			return false;
		nnode->tag = mnode->tag;
		nnode->upper = mnode->upper;

		xsect = mnode->nkeys / 2;
		if (mnode->tag == TAG_MBTREE_LEAF)
		{
			/* copy larger half of the btree leaf */
			memcpy(nnode->keys, mnode->keys + xsect,
				   sizeof(uint32_t) * (mnode->nkeys - xsect));
			memcpy(nnode->items, mnode->items + xsect,
				   sizeof(uint64_t) * (mnode->nkeys - xsect + 1));
			nnode->nkeys = mnode->nkeys - xsect;
			mnode->nkeys = xsect;
			mnode->items[xsect] = mblock_addr_to_offset(mbsup, nnode);

			pkey = mnode->keys[mnode->nkeys - 1];	/* key of the nnode */
		}
		else
		{
			/* copy larger half of the btree node */
			memcpy(nnode->keys, mnode->keys + xsect + 1,
				   sizeof(uint32_t) * (mnode->nkeys - xsect - 1));
			memcpy(nnode->items, mnode->items + xsect + 1,
				   sizeof(uint64_t) * (mnode->nkeys - xsect));
			nnode->nkeys = mnode->nkeys - (xsect + 1);
			mnode->nkeys = xsect;

			children_reparent(mbsup, nnode, nnode);

			pkey = mnode->keys[xsect];				/* key of the nnode */
		}
		/* insert nnode into pnode next to mnode */
		index = find_item_index(mbsup, pnode, mnode);

		memmove(pnode->keys + index + 1, pnode->keys + index,
				sizeof(uint32_t) * (pnode->nkeys - index));
		memmove(pnode->items + index + 2, pnode->items + index + 1,
				sizeof(uint64_t) * (pnode->nkeys - index));
		pnode->keys[index] = pkey;
		pnode->items[index + 1] = mblock_addr_to_offset(mbsup, nnode);
		pnode->nkeys++;
	}
	return true;
}

/*
 * mbtree_insert
 *
 *
 *
 */
bool
mbtree_insert(void *handle, uint32_t key, uint64_t item)
{
	mbtree_super   *mbsup = handle;
	mbtree_node	   *mnode;
	mbtree_node	   *tnode;
	int				index, j;

retry:
	mnode = mblock_offset_to_addr(mbsup, mbsup->root);
	while (mnode->tag == TAG_MBTREE_NODE)
	{
		index = find_key_index(mnode, key);

		mnode = mblock_offset_to_addr(mbsup, mnode->items[index]);
	}
	assert(mnode->tag == TAG_MBTREE_LEAF);

	if (mnode->nkeys == MBTREE_NUM_KEYS)
	{
		if (!mbtree_divide(mbsup, mnode))
			return false;

		goto retry;
	}
	index = find_key_index(mnode, key);

	/*
	 * Check duplication of the key/item pair
	 */
	j = index;
	tnode = mnode;
	while (j < tnode->nkeys && tnode->keys[j] == key)
	{
		if (tnode->items[j] == item)
			return false;

		if (++j == tnode->nkeys && tnode->items[j] != 0)
		{
			tnode = mblock_offset_to_addr(mbsup, tnode->items[j]);
			j = 0;
		}
	}

	/*
	 * Insert a key/item pair
	 */
	memmove(mnode->keys + index + 1, mnode->keys + index,
			sizeof(uint32_t) * (mnode->nkeys - index));
	memmove(mnode->items + index + 1, mnode->items + index,
			sizeof(uint64_t) * (mnode->nkeys - index + 1));
	mnode->keys[index] = key;
	mnode->items[index] = item;
	mnode->nkeys++;

	return true;
}

/*
 * mbtree_merge
 *
 *
 *
 */
static void
mbtree_merge(mbtree_super *mbsup, mbtree_node *mnode)
{
	mbtree_node	   *pnode;
	mbtree_node	   *cnode;
	mbtree_node	   *lnode;
	mbtree_node	   *rnode;
	int				index, nmove;

	if (mnode->nkeys > MBTREE_NUM_KEYS / 2)
		return;

	/*
	 * If the root node has only one node (not a leaf), it tries to
	 * use the child as a new root to reduce unnecessary depth of
	 * the B+ tree.
	 */
	if (mnode->nkeys == 0 && mnode->tag == TAG_MBTREE_NODE)
	{
		/* only happen on root node */
		assert(mnode->upper == 0);
		assert(mbsup->root == mblock_addr_to_offset(mbsup, mnode));

		cnode = mblock_offset_to_addr(mbsup, mnode->items[0]);
		cnode->upper = 0;
		mbsup->root = mblock_addr_to_offset(mbsup, cnode);

		mblock_free(mbsup, mnode);

		return;
	}
	if (mnode->upper == 0)
		return;

	/*
	 * Select two nodes to be merged. If @mnode is on the edge
	 * of parent node, no options for its buddy. If @mnode has
	 * buddies on left/right side, it prefer to merge with the
	 * node which has smaller number of elements.
	 */
	pnode = mblock_offset_to_addr(mbsup, mnode->upper);
	index = find_item_index(mbsup, pnode, mnode);
	if (index == pnode->nkeys)
		index--;
	else if (index > 0)
	{
		lnode = mblock_offset_to_addr(mbsup, pnode->items[index - 1]);
		rnode = mblock_offset_to_addr(mbsup, pnode->items[index + 1]);
		if (lnode->nkeys < rnode->nkeys)
			index--;
	}
	lnode = mblock_offset_to_addr(mbsup, pnode->items[index]);
	rnode = mblock_offset_to_addr(mbsup, pnode->items[index + 1]);
	assert(lnode->tag == rnode->tag);

	if (lnode->tag == TAG_MBTREE_LEAF)
	{
		if (lnode->nkeys + rnode->nkeys <= MBTREE_NUM_KEYS)
		{
			/* Try to merge two leafs into one */
			memcpy(lnode->keys + lnode->nkeys, rnode->keys,
				   sizeof(uint32_t) * rnode->nkeys);
			memcpy(lnode->items + lnode->nkeys, rnode->items,
				   sizeof(uint64_t) * (rnode->nkeys + 1));
			lnode->nkeys += rnode->nkeys;

			mblock_free(mbsup, rnode);

			/* Remove rnode from pnode */
			memmove(pnode->keys + index, pnode->keys + index + 1,
					sizeof(uint32_t) * (pnode->nkeys - index));
			memmove(pnode->items + index + 1, pnode->items + index + 2,
					sizeof(uint64_t) * (pnode->nkeys - index));
			pnode->nkeys--;
		}
		else if (lnode->nkeys > rnode->nkeys)
		{
			/* Move items from lnode to rnode */
			nmove = (lnode->nkeys - rnode->nkeys) / 2;
			if (nmove > 0)
			{
				memmove(rnode->keys + nmove, rnode->keys,
						sizeof(uint32_t) * rnode->nkeys);
				memmove(rnode->items + nmove, rnode->items,
						sizeof(uint64_t) * (rnode->nkeys + 1));
				memmove(rnode->keys, lnode->keys + lnode->nkeys - nmove,
						sizeof(uint32_t) * nmove);
				memmove(rnode->items, lnode->items + lnode->nkeys - nmove,
						sizeof(uint64_t) * nmove);
				rnode->nkeys += nmove;
				lnode->nkeys -= nmove;
				lnode->items[lnode->nkeys] = mblock_addr_to_offset(mbsup, rnode);

				pnode->keys[index] = lnode->keys[lnode->nkeys - 1];
			}
		}
		else
		{
			/* Move items from rnode to lnode */
			nmove = (rnode->nkeys - lnode->nkeys) / 2;
			if (nmove > 0)
			{
				memmove(lnode->keys + lnode->nkeys, rnode->keys,
						sizeof(uint32_t) * nmove);
				memmove(lnode->items + lnode->nkeys, rnode->items,
						sizeof(uint64_t) * nmove);
				memmove(rnode->keys, rnode->keys + nmove,
						sizeof(uint32_t) * (rnode->nkeys - nmove));
				memmove(rnode->items, rnode->items + nmove,
						sizeof(uint64_t) * (rnode->nkeys - nmove + 1));
				lnode->nkeys += nmove;
				rnode->nkeys -= nmove;
				lnode->items[lnode->nkeys] = mblock_addr_to_offset(mbsup, rnode);

				pnode->keys[index] = lnode->keys[lnode->nkeys - 1];
			}
		}
	}
	else
	{
		if (lnode->nkeys + rnode->nkeys < MBTREE_NUM_KEYS)
		{
			/* Try to merge two nodes into one */
			lnode->keys[lnode->nkeys] = pnode->keys[index];
			memcpy(lnode->keys + lnode->nkeys + 1, rnode->keys,
				   sizeof(uint32_t) * rnode->nkeys);
			memcpy(lnode->items + lnode->nkeys + 1, rnode->items,
				   sizeof(uint64_t) * (rnode->nkeys + 1));
			lnode->nkeys += rnode->nkeys + 1;

			mblock_free(mbsup, rnode);

			/* Remove rnode from pnode */
			memmove(pnode->keys + index + 1, pnode->keys + index + 2,
					sizeof(uint32_t) * (pnode->nkeys - index - 1));
			memmove(pnode->items + index + 1, pnode->items + index + 2,
					sizeof(uint64_t) * (pnode->nkeys - index));
			pnode->nkeys--;

			children_reparent(mbsup, lnode, lnode);
		}
		else if (lnode->nkeys > rnode->nkeys)
		{
			/* Move items from lnode to rnode */
			nmove = (lnode->nkeys - rnode->nkeys) / 2;
			if (nmove > 0)
			{
				memmove(rnode->keys + nmove, rnode->keys,
						sizeof(uint32_t) * rnode->nkeys);
				memmove(rnode->items + nmove, rnode->items,
						sizeof(uint64_t) * (rnode->nkeys + 1));
				rnode->keys[nmove - 1] = pnode->keys[index];
				pnode->keys[index] = lnode->keys[lnode->nkeys - nmove];
				memmove(rnode->keys, lnode->keys + lnode->nkeys - nmove + 1,
						sizeof(uint64_t) * (nmove - 1));
				memmove(rnode->items, lnode->items + lnode->nkeys - nmove,
						sizeof(uint64_t) * nmove);
				rnode->nkeys += nmove;
				lnode->nkeys -= nmove;

				children_reparent(mbsup, rnode, rnode);
			}
		}
		else
		{
			/* Move items from rnode to lnode */
			nmove = (rnode->nkeys - lnode->nkeys) / 2;
			if (nmove > 0)
			{
				lnode->keys[lnode->nkeys] = pnode->keys[index];
				pnode->keys[index] = rnode->keys[nmove - 1];

				memmove(lnode->keys + lnode->nkeys + 1, rnode->keys,
						sizeof(uint32_t) * (nmove - 1));
				memmove(lnode->items + lnode->nkeys + 1, rnode->items,
						sizeof(uint64_t) * nmove);
				memmove(rnode->keys, rnode->keys + nmove,
						sizeof(uint32_t) * (rnode->nkeys - nmove));
				memmove(rnode->items, rnode->items + nmove,
						sizeof(uint64_t) * (rnode->nkeys - nmove + 1));
				lnode->nkeys += nmove;
				rnode->nkeys -= nmove;

				children_reparent(mbsup, lnode, lnode);
			}
		}
	}
}

/*
 * mbtree_delete
 *
 * It tries to delete the specified key/item pair.
 */
static bool
mbtree_delete_internal(mbtree_super *mbsup, mbtree_node *mnode,
					   uint32_t key, uint64_t item)
{
	mbtree_node	   *cnode;
	int				index;

	/*
	 * If @mnode is node, we walk down into next level recursively.
	 * In the result, if it can causes the node merging, we try to
	 * merge two nodes.
	 */
	if (mnode->tag == TAG_MBTREE_NODE)
	{
		index = find_key_index(mnode, key);

		cnode = mblock_offset_to_addr(mbsup, mnode->items[index]);

		if (!mbtree_delete_internal(mbsup, cnode, key, item))
			return false;

		mbtree_merge(mbsup, mnode);

		return true;
	}

	/*
	 * Leaf node to be removed
	 */
	index = find_key_index(mnode, key);
	while (mnode->keys[index] == key)
	{
		/* remove an item */
		if (mnode->items[index] == item)
		{
			memmove(mnode->keys + index, mnode->keys + index + 1,
					sizeof(uint32_t) * (mnode->nkeys - index - 1));
			memmove(mnode->items + index, mnode->items + index + 1,
					sizeof(uint64_t) * (mnode->nkeys - index));
			mnode->nkeys--;

			mbtree_merge(mbsup, mnode);

			return true;
		}
		if (++index == mnode->nkeys)
		{
			if (mnode->items[mnode->nkeys] == 0)
				break;

			mnode = mblock_offset_to_addr(mbsup, mnode->items[mnode->nkeys]);
			index = 0;
		}
	}
	return false;	/* not found */
}

bool
mbtree_delete(void *handle, uint32_t key, uint64_t item)
{
	mbtree_super   *mbsup = handle;
	mbtree_node	   *mnode = mblock_offset_to_addr(mbsup, mbsup->root);

	if (mnode->nkeys == 0)
	{
		/* only happen when root node */
		assert(mnode->upper == 0);
		return false;
	}
	return mbtree_delete_internal(mbsup, mnode, key, item);
}

/*
 * mbtree_create
 *
 *
 */
void *
mbtree_init(int fdesc, size_t block_size)
{
	mbtree_super   *mbsup;
	mbtree_node	   *mnode;

	mbsup = mblock_init(fdesc, block_size, sizeof(mbtree_super));
	if (!mbsup)
		return NULL;

	if (mbsup->root == 0)
	{
		mnode = mblock_alloc(mbsup, sizeof(mbtree_node));
		if (!mnode)
		{
			mblock_unmap(mbsup);
			return NULL;
		}
		mnode->tag = TAG_MBTREE_LEAF;
		mnode->nkeys = 0;
		mnode->upper = 0;
		memset(mnode->keys, 0, sizeof(mnode->keys));
		memset(mnode->items, 0, sizeof(mnode->items));

		mbsup->root = mblock_addr_to_offset(mbsup, mnode);
	}
	return mbsup;
}

#if 0
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static void *mbroot = NULL;

static bool
mbtree_cb(void *data, size_t size)
{
	mbtree_node	   *mnode = data;

	if (mnode->upper == 0)
	{
		printf("find mbtree root at %p\n", data);
		mbroot = mnode;
	}
	return true;
}

int main(int argc, const char *argv[])
{
	uint32_t	key;
	uint64_t	item;
	void	   *handle;
	int			fd;
	struct stat	stbuf;

	if (argc < 2)
		goto usage;

	fd = open(argv[1], O_RDWR);
	if (fd < 0)
	{
		printf("failed to open '%s'\n", argv[1]);
		return 1;
	}
	if (fstat(fd, &stbuf) != 0)
	{
		printf("failed to stat '%s'\n", argv[1]);
		return 1;
	}

	handle = mbtree_init(fd, stbuf.st_size);
	if (!handle)
	{
		printf("failed to init mblock\n");
		return 1;
	}

	if (argc == 4 && strcmp(argv[2], "get") == 0)
	{
		mbtree_scan	scan;
		uint32_t	key;

		key = atol(argv[3]);
		memset(&scan, 0, sizeof(scan));
		while (mbtree_lookup(handle, key, &scan))
		{
			printf("==> GET key=%" PRIu32 " value=%" PRIu64 "\n",
				   scan.key, scan.item);
		}
		mbtree_dump(handle);
		return 0;
	}
	else if (argc == 5 && strcmp(argv[2], "ins") == 0)
	{
		key = atol(argv[3]);
		item = atoll(argv[4]);

		printf("==> INSERT (key=%" PRIu32 ", value=%" PRIu64 ")\n", key, item);
		if (!mbtree_insert(handle, key, item))
		{
			printf("failed to mbtree_insert\n");
			return 1;
		}
		mbtree_dump(handle);
		mblock_dump(handle);
		return 0;
	}
	else if (argc == 5 && strcmp(argv[2], "del") == 0)
	{
		key = atol(argv[3]);
        item = atoll(argv[4]);

		printf("==> DELETE (key=%" PRIu32 ", value=%" PRIu64 ")\n", key, item);
		if (!mbtree_delete(handle, key, item))
		{
			printf("failed to mbtree_delete\n");
			return 1;
		}
		mbtree_dump(handle);
		mblock_dump(handle);
		return 0;
	}

usage:
	printf("usage: %s <filename> get <key>\n", argv[0]);
	printf("       %s <filename> ins <key> <value>\n", argv[0]);
	printf("       %s <filename> del <key> <value>\n", argv[0]);

	return 1;
}
#endif
