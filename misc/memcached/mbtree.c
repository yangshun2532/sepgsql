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

#define MBTREE_NUM_KEYS		5

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

static int
find_key_index(void *handle, mbtree_node *mnode, uint32_t key)
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

static int
find_item_index(void *handle, mbtree_node *pnode, mbtree_node *cnode)
{
	uint64_t	item = addr_to_offset(handle, cnode);
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
children_reparent(void *handle, mbtree_node *mnode, mbtree_node *pnode)
{
	uint64_t	new_upper = addr_to_offset(handle, pnode);
	int			i;

	for (i=0; i <= mnode->nkeys; i++)
	{
		mbtree_node *cnode = offset_to_addr(handle, mnode->items[i]);

		cnode->upper = new_upper;
	}
}

uint64_t
mbtree_lookup(void *handle, void *mbroot, uint32_t key, mbtree_scan *scan)
{
	mbtree_node	   *mnode = mbroot;
	int				index;

	while (mnode->tag == TAG_MBTREE_NODE)
	{
		index = find_key_index(handle, mnode, key);

		mnode = offset_to_addr(handle, mnode->items[index]);
	}

	index = find_key_index(handle, mnode, key);
	if (mnode->keys[index] != key)
		return 0;	/* not found */

	if (scan)
	{
		scan->key = key;
		scan->mnode = addr_to_offset(handle, mnode);
		scan->index = index;
	}
	return mnode->items[index];
}

uint64_t
mbtree_next(void *handle, mbtree_scan *scan)
{
	mbtree_node	   *mnode = offset_to_addr(handle, scan->mnode);
	int				index = scan->index + 1;

	if (mnode->nkeys == index)
	{
		mnode = offset_to_addr(handle, mnode->items[index]);
		index = 0;
	}
	if (mnode->keys[index] == scan->key)
	{
		scan->mnode = addr_to_offset(handle, mnode);
		scan->index = index;
		
		return mnode->items[index];
	}
	return 0;
}

static void
mbtree_dump_node(void *handle, mbtree_node *mnode, int nestlv)
{
	mbtree_node	   *cnode;
	int				i;

	if (mnode->tag == TAG_MBTREE_LEAF)
	{
		printf("%*sleaf(0x%" PRIx64 ", nkeys=%d, upper=0x%" PRIx64 ") {\n", nestlv, "",
			   addr_to_offset(handle, mnode), mnode->nkeys, mnode->upper);
		for (i=0; i < mnode->nkeys; i++)
			printf("%*skey=%" PRIu32 ", value=%" PRIu64 "\n", nestlv + 2, "",
				   mnode->keys[i], mnode->items[i]);
		printf("%*s} next=0x%" PRIx64 "\n", nestlv, "",
			   mnode->items[mnode->nkeys]);
	}
	else
	{
		printf("%*snode(0x%" PRIx64 ", nkeys=%d, upper=0x%" PRIx64 ") {\n", nestlv, "",
			   addr_to_offset(handle, mnode), mnode->nkeys, mnode->upper);
		for (i=0; i <= mnode->nkeys; i++)
		{
			cnode = offset_to_addr(handle, mnode->items[i]);
			mbtree_dump_node(handle, cnode, nestlv+2);

			if (i < mnode->nkeys)
				printf("%*s* key=%" PRIu32 "\n", nestlv + 2, "", mnode->keys[i]);
		}
		printf("%*s}\n", nestlv, "");
	}
}

void
mbtree_dump(void *handle, void *mbroot)
{
	mbtree_node	   *mnode = mbroot;

	mbtree_dump_node(handle, mnode, 0);
}

static bool
mbtree_divide(void *handle, mbtree_node *mnode)
{
	assert(mnode->nkeys == MBTREE_NUM_KEYS);

	if (!mnode->upper)
	{
		mbtree_node	   *lnode;
		mbtree_node	   *rnode;
		uint32_t		pkey;
		int				xsect;

		lnode = mblock_alloc(handle, sizeof(mbtree_node));
		if (!lnode)
			return false;

		rnode = mblock_alloc(handle, sizeof(mbtree_node));
		if (!rnode)
		{
			mblock_free(handle, lnode);
			return false;
		}

		lnode->tag = rnode->tag = mnode->tag;
		lnode->upper = rnode->upper = addr_to_offset(handle, mnode);

		xsect = mnode->nkeys / 2;
		if (mnode->tag == TAG_MBTREE_LEAF)
		{
			/* copy smaller half to lnode */
			memcpy(lnode->keys, mnode->keys,
				   sizeof(uint32_t) * xsect);
			memcpy(lnode->items, mnode->items,
				   sizeof(uint64_t) * xsect);
			lnode->nkeys = xsect;
			lnode->items[lnode->nkeys] = addr_to_offset(handle, rnode);

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
			children_reparent(handle, lnode, lnode);

			/* copy larger half to rnode */
			memcpy(rnode->keys, mnode->keys + xsect + 1,
				   sizeof(uint32_t) * (mnode->nkeys - xsect - 1));
			memcpy(rnode->items, mnode->items + xsect + 1,
				   sizeof(uint64_t) * (mnode->nkeys - xsect));
			rnode->nkeys = mnode->nkeys - xsect - 1;
			children_reparent(handle, rnode, rnode);
			pkey = mnode->keys[xsect];
		}
		/* set up root node */
		mnode->tag = TAG_MBTREE_NODE;
		mnode->nkeys = 1;
		mnode->keys[0] = pkey;
		mnode->items[0] = addr_to_offset(handle, lnode);
		mnode->items[1] = addr_to_offset(handle, rnode);
	}
	else
	{
		mbtree_node	   *pnode;
		mbtree_node	   *nnode;
		uint32_t		pkey;
		int				xsect, index;

		pnode = offset_to_addr(handle, mnode->upper);
		if (pnode->nkeys == MBTREE_NUM_KEYS)
		{
			if (!mbtree_divide(handle, pnode))
				return false;
			/* memo: the parent might be moved */
			pnode = offset_to_addr(handle, mnode->upper);
		}
		nnode = mblock_alloc(handle, sizeof(mbtree_node));
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
			mnode->items[xsect] = addr_to_offset(handle, nnode);

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

			children_reparent(handle, nnode, nnode);

			pkey = mnode->keys[xsect];				/* key of the nnode */
		}
		/* insert nnode into pnode next to mnode */
		index = find_item_index(handle, pnode, mnode);

		memmove(pnode->keys + index + 1, pnode->keys + index,
				sizeof(uint32_t) * (pnode->nkeys - index));
		memmove(pnode->items + index + 2, pnode->items + index + 1,
				sizeof(uint64_t) * (pnode->nkeys - index));
		pnode->keys[index] = pkey;
		pnode->items[index + 1] = addr_to_offset(handle, nnode);
		pnode->nkeys++;
	}
	return true;
}

bool
mbtree_insert(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_node	   *mnode;
	int				index;

retry:
	mnode = mbroot;
	while (mnode->tag == TAG_MBTREE_NODE)
	{
		index = find_key_index(handle, mnode, key);

		mnode = offset_to_addr(handle, mnode->items[index]);
	}
	assert(mnode->tag == TAG_MBTREE_LEAF);

	if (mnode->nkeys == MBTREE_NUM_KEYS)
	{
		if (!mbtree_divide(handle, mnode))
			return false;
		goto retry;
	}

	/* insert a key/item pair */
	index = find_key_index(handle, mnode, key);

	memmove(mnode->keys + index + 1, mnode->keys + index,
			sizeof(uint32_t) * (mnode->nkeys - index));
	memmove(mnode->items + index + 1, mnode->items + index,
			sizeof(uint64_t) * (mnode->nkeys - index + 1));
	mnode->keys[index] = key;
	mnode->items[index] = item;
	mnode->nkeys++;

	return true;
}

static void
mbtree_merge(void *handle, mbtree_node *mnode)
{
	mbtree_node	   *pnode;
	mbtree_node	   *cnode;
	mbtree_node	   *lnode;
	mbtree_node	   *rnode;
	int				index, nmove;

	if (mnode->nkeys > MBTREE_NUM_KEYS / 2)
		return;
	if (mnode->nkeys == 0 && mnode->tag == TAG_MBTREE_NODE)
	{
		/* only happen on root node */
		assert(mnode->upper == 0);

		printf("try to pull up mnode->item[0] = 0x%lx\n", mnode->items[0]);

		cnode = offset_to_addr(handle, mnode->items[0]);

		printf("cnode->nkeys = %d\n", cnode->nkeys);

		memcpy(mnode->keys, cnode->keys,
			   sizeof(uint32_t) * cnode->nkeys);
		memcpy(mnode->items, cnode->items,
			   sizeof(uint64_t) * (cnode->nkeys + 1));
		mnode->nkeys = cnode->nkeys;
		mnode->tag = cnode->tag;

		if (mnode->tag == TAG_MBTREE_NODE)
			children_reparent(handle, mnode, mnode);

		mblock_free(handle, cnode);
	}
	if (mnode->upper == 0)
		return;

	pnode = offset_to_addr(handle, mnode->upper);
	index = find_item_index(handle, pnode, mnode);
	if (index == pnode->nkeys)
		index--;
	else if (index > 0)
	{
		lnode = offset_to_addr(handle, pnode->items[index - 1]);
		rnode = offset_to_addr(handle, pnode->items[index + 1]);
		if (lnode->nkeys < rnode->nkeys)
			index--;
	}
	lnode = offset_to_addr(handle, pnode->items[index]);
	rnode = offset_to_addr(handle, pnode->items[index + 1]);
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

			mblock_free(handle, rnode);

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
				lnode->items[lnode->nkeys] = addr_to_offset(handle, rnode);

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
				lnode->items[lnode->nkeys] = addr_to_offset(handle, rnode);

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

			mblock_free(handle, rnode);

			/* Remove rnode from pnode */
			memmove(pnode->keys + index + 1, pnode->keys + index + 2,
					sizeof(uint32_t) * (pnode->nkeys - index - 1));
			memmove(pnode->items + index + 1, pnode->items + index + 2,
					sizeof(uint64_t) * (pnode->nkeys - index));
			pnode->nkeys--;

			children_reparent(handle, lnode, lnode);
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

				children_reparent(handle, rnode, rnode);
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

				children_reparent(handle, lnode, lnode);
			}
		}
	}
}

bool
mbtree_delete(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_node	   *mnode = mbroot;
	mbtree_node	   *cnode;
	int				index;

	if (mnode->nkeys == 0)
	{
		/* only happen when root node */
		assert(mnode->upper == 0);
		return false;
	}
	if (mnode->tag == TAG_MBTREE_NODE)
	{
		index = find_key_index(handle, mnode, key);

		cnode = offset_to_addr(handle, mnode->items[index]);

		if (!mbtree_delete(handle, cnode, key, item))
			return false;

		mbtree_merge(handle, mnode);

		return true;
	}
	/*
	 * Leaf node to be removed
	 */
	index = find_key_index(handle, mnode, key);
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

			mbtree_merge(handle, mnode);

			return true;
		}
		if (++index == mnode->nkeys)
		{
			if (mnode->items[mnode->nkeys] == 0)
				break;

			mnode = offset_to_addr(handle, mnode->items[mnode->nkeys]);
			index = 0;
		}
	}
	return false;	/* not found */
}

void *
mbtree_create(void *handle)
{
	mbtree_node	   *mbroot = mblock_alloc(handle, sizeof(mbtree_node));

	if (!mbroot)
		return NULL;

	mbroot->tag = TAG_MBTREE_LEAF;
	mbroot->nkeys = 0;
	mbroot->upper = 0;
	memset(mbroot->keys, 0, sizeof(mbroot->keys));
	memset(mbroot->items, 0, sizeof(mbroot->items));

	return mbroot;
}

#if 1
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

	handle =  mblock_init(fd, stbuf.st_size, true, mbtree_cb);
	if (!handle)
	{
		printf("failed to init mblock\n");
		return 1;
	}

	if (!mbroot)
		mbroot = mbtree_create(handle);

	if (argc == 4 && strcmp(argv[2], "get") == 0)
	{
		mbtree_dump(handle, mbroot);
		return 0;
	}
	else if (argc == 5 && strcmp(argv[2], "ins") == 0)
	{
		key = atol(argv[3]);
		item = atoll(argv[4]);

		printf("==> INSERT (key=%" PRIu32 ", value=%" PRIu64 ")\n", key, item);
		if (!mbtree_insert(handle, mbroot, key, item))
		{
			printf("failed to mbtree_insert\n");
			return 1;
		}
		mbtree_dump(handle, mbroot);
		return 0;
	}
	else if (argc == 5 && strcmp(argv[2], "del") == 0)
	{
		key = atol(argv[3]);
        item = atoll(argv[4]);

		printf("==> DELETE (key=%" PRIu32 ", value=%" PRIu64 ")\n", key, item);
		if (!mbtree_delete(handle, mbroot, key, item))
		{
			printf("failed to mbtree_delete\n");
			return 1;
		}
		mbtree_dump(handle, mbroot);
		return 0;
	}

usage:
	printf("usage: %s <filename> get <key>\n", argv[0]);
	printf("       %s <filename> ins <key> <value>\n", argv[0]);
	printf("       %s <filename> del <key> <value>\n", argv[0]);

	return 1;
}
#endif
