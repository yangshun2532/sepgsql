/*
 * mbtree.c
 *
 * B-plus Tree routines
 */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "selinux_engine.h"

static int
find_key_index(mchunk_t *mchunk, uint32_t key)
{
	int		min = 0;
	int		max = mchunk->btree.nkeys;
	int		index;

	assert(mchunk->tag == MCHUNK_TAG_BTREE);
	if (mchunk->btree.nkeys == 0)
	{
		assert(mchunk->btree.parent == 0);
		return 0;
	}

	do {
		index = (min + max) / 2;

		if (mchunk->btree.keys[index] < key)
			min = index + 1;
		else
			max = index;
	} while (min != max);

	return min;
}

static int
find_child_index(mhead_t *mhead, mchunk_t *mchunk)
{
	mchunk_t   *pchunk = offset_to_addr(mhead, mchunk->btree.parent);
	uint64_t	offset = addr_to_offset(mhead, mchunk);
	int			index;

	assert(pchunk->tag == MCHUNK_TAG_BTREE && !pchunk->btree.is_leaf);
	for (index = 0; index <= pchunk->btree.nkeys; index++)
	{
		if (pchunk->btree.items[index] == offset)
			return index;
	}
	assert(false);
}

static void
children_reparent(mhead_t *mhead, mchunk_t *mchunk)
{
	uint64_t	parent = addr_to_offset(mhead, mchunk);
	int			index;

	for (index = 0; index <= mchunk->btree.nkeys; index++)
	{
		mchunk_t *cchunk = offset_to_addr(mhead, mchunk->btree.items[index]);

		cchunk->btree.parent = parent;
	}
}

bool
mbtree_lookup(mhead_t *mhead, mbtree_scan *scan)
{
	mchunk_t   *mchunk;
	int			index;

	if (scan->mnode == 0)
	{
		mchunk = (mchunk_t *)mhead->super_block;
		assert(mchunk->tag == MCHUNK_TAG_BTREE);

		while (!mchunk->btree.is_leaf)
		{
			index = find_key_index(mchunk, scan->key);

			mchunk = offset_to_addr(mhead, mchunk->btree.items[index]);
		}
		index = find_key_index(mchunk, scan->key);
		if (index == mchunk->btree.nkeys)
			return false;

		scan->mnode = addr_to_offset(mhead, mchunk);
		scan->index = index;
		scan->key = mchunk->btree.keys[index];
		scan->item = mchunk->btree.items[index];
	}
	else
	{
		mchunk = offset_to_addr(mhead, scan->mnode);
		assert(mchunk_is_btree(mchunk) && mchunk->btree.is_leaf);
		index = scan->index + 1;

		if (index == mchunk->btree.nkeys)
		{
			mchunk = offset_to_addr(mhead, mchunk->btree.items[index]);
			if (!mchunk)
				return false;
			index = 0;
		}
		scan->mnode = addr_to_offset(mhead, mchunk);
		scan->index = index;
		scan->key = mchunk->btree.keys[index];
		scan->item = mchunk->btree.items[index];
	}
	return true;
}

static bool
mbtree_split(mhead_t *mhead, mchunk_t *mchunk)
{
	if (!mchunk->btree.parent)
	{
		mchunk_t   *lchunk;
		mchunk_t   *rchunk;
		uint32_t	pkey;
		int			xsect;

		lchunk = mblock_alloc(mhead, MCHUNK_TAG_BTREE, sizeof(mchunk_t));
		if (!lchunk)
			return false;

		rchunk = mblock_alloc(mhead, MCHUNK_TAG_BTREE, sizeof(mchunk_t));
		if (!rchunk)
		{
			mblock_free(mhead, lchunk);
			return false;
		}
		lchunk->btree.is_leaf = mchunk->btree.is_leaf;
		rchunk->btree.is_leaf = mchunk->btree.is_leaf;
		lchunk->btree.parent = addr_to_offset(mhead, mchunk);
		rchunk->btree.parent = addr_to_offset(mhead, mchunk);

		xsect = mchunk->btree.nkeys / 2;
		if (mchunk->btree.is_leaf)
		{
			/* copy smaller half */
			memcpy(lchunk->btree.keys, mchunk->btree.keys,
				   sizeof(uint32_t) * xsect);
			memcpy(lchunk->btree.items, mchunk->btree.items,
				   sizeof(uint64_t) * xsect);
			lchunk->btree.nkeys = xsect;
			lchunk->btree.items[lchunk->btree.nkeys]
				= addr_to_offset(mhead, rchunk);

			/* copy larger half */
			memcpy(rchunk->btree.keys, mchunk->btree.keys + xsect,
				   sizeof(uint32_t) * (mchunk->btree.nkeys - xsect));
			memcpy(rchunk->btree.items, mchunk->btree.items + xsect,
				   sizeof(uint64_t) * (mchunk->btree.nkeys - xsect));
			rchunk->btree.nkeys = mchunk->btree.nkeys - xsect;
			rchunk->btree.items[rchunk->btree.nkeys] = 0;

			pkey = lchunk->btree.keys[lchunk->btree.nkeys - 1];
		}
		else
		{
			/* copy smaller half to lnode */
			memcpy(lchunk->btree.keys, mchunk->btree.keys,
				   sizeof(uint32_t) * xsect);
			memcpy(lchunk->btree.items, mchunk->btree.items,
				   sizeof(uint64_t) * (xsect + 1));
			lchunk->btree.nkeys = xsect;
            children_reparent(mhead, lchunk);

            /* copy larger half to rnode */
			memcpy(rchunk->btree.keys, mchunk->btree.keys + xsect + 1,
				   sizeof(uint32_t) * (mchunk->btree.nkeys - xsect - 1));
			memcpy(rchunk->btree.items, mchunk->btree.items + xsect + 1,
				   sizeof(uint64_t) * (mchunk->btree.nkeys - xsect));
			rchunk->btree.nkeys = mchunk->btree.nkeys - xsect - 1;
			children_reparent(mhead, rchunk);

			pkey = mchunk->btree.keys[xsect];
		}
		/* fix up root node */
		mchunk->btree.is_leaf = false;
		mchunk->btree.nkeys = 1;
		mchunk->btree.keys[0] = pkey;
		mchunk->btree.items[0] = addr_to_offset(mhead, lchunk);
		mchunk->btree.items[1] = addr_to_offset(mhead, rchunk);
	}
	else
	{
		mchunk_t   *pchunk;
		mchunk_t   *nchunk;
		uint32_t	pkey;
		int			xsect, index;

		/*
         * In the case when non-root node, we need to make sure
         * the parent node has a slot to store the new node at
         * least. If the parent is also full, we recursively
         * divide the root node.
         * Note that @mnode might be reparented during the divide.
         */
		pchunk = offset_to_addr(mhead, mchunk->btree.parent);
		if (pchunk->btree.nkeys == MBTREE_NUM_KEYS)
        {
			if (!mbtree_split(mhead, pchunk))
				return false;
			pchunk = offset_to_addr(mhead, mchunk->btree.parent);
        }

        nchunk = mblock_alloc(mhead, MCHUNK_TAG_BTREE, sizeof(mchunk_t));
        if (!nchunk)
            return false;
		nchunk->btree.is_leaf = mchunk->btree.is_leaf;
		nchunk->btree.parent = mchunk->btree.parent;

		xsect = mchunk->btree.nkeys / 2;
		if (mchunk->btree.is_leaf)
		{
			/* copy the larger half */
			memcpy(nchunk->btree.keys, mchunk->btree.keys + xsect,
				   sizeof(uint32_t) * (mchunk->btree.nkeys - xsect));
            memcpy(nchunk->btree.items, mchunk->btree.items + xsect,
                   sizeof(uint64_t) * (mchunk->btree.nkeys - xsect + 1));
            nchunk->btree.nkeys = mchunk->btree.nkeys - xsect;
            mchunk->btree.nkeys = xsect;
            mchunk->btree.items[xsect] = addr_to_offset(mhead, nchunk);

			pkey = mchunk->btree.keys[mchunk->btree.nkeys - 1];
        }
        else
        {
			/* copy the larger half */
			memcpy(nchunk->btree.keys, mchunk->btree.keys + xsect + 1,
                   sizeof(uint32_t) * (mchunk->btree.nkeys - xsect - 1));
            memcpy(nchunk->btree.items, mchunk->btree.items + xsect + 1,
                   sizeof(uint64_t) * (mchunk->btree.nkeys - xsect));
            nchunk->btree.nkeys = mchunk->btree.nkeys - (xsect + 1);
			mchunk->btree.nkeys = xsect;

			children_reparent(mhead, nchunk);

			pkey = mchunk->btree.keys[xsect];
        }
        /* insert nnode into pnode next to mnode */
		index = find_child_index(mhead, mchunk);

        memmove(pchunk->btree.keys + index + 1, pchunk->btree.keys + index,
				sizeof(uint32_t) * (pchunk->btree.nkeys - index));
		memmove(pchunk->btree.items + index + 2, pchunk->btree.items + index + 1,
				sizeof(uint64_t) * (pchunk->btree.nkeys - index));
        pchunk->btree.keys[index] = pkey;
        pchunk->btree.items[index + 1] = addr_to_offset(mhead, nchunk);
		pchunk->btree.nkeys++;
	}
	return true;
}

bool
mbtree_insert(mhead_t *mhead, uint32_t key, uint64_t item)
{
	mchunk_t   *mchunk;
	int			index;

retry:
	mchunk = (mchunk_t *)mhead->super_block;
	while (!mchunk->btree.is_leaf)
	{
		index = find_key_index(mchunk, key);

		mchunk = offset_to_addr(mhead, mchunk->btree.items[index]);
	}

	if (mchunk->btree.nkeys == MBTREE_NUM_KEYS)
	{
		if (!mbtree_split(mhead, mchunk))
			return false;
		goto retry;
	}
	index = find_key_index(mchunk, key);

	/*
	 * insert a pair of key/item
	 */
	memmove(mchunk->btree.keys + index + 1, mchunk->btree.keys + index,
			sizeof(uint32_t) * (mchunk->btree.nkeys - index));
	memmove(mchunk->btree.items + index + 1, mchunk->btree.items + index,
			sizeof(uint64_t) * (mchunk->btree.nkeys - index + 1));
	mchunk->btree.keys[index] = key;
	mchunk->btree.items[index] = item;
	mchunk->btree.nkeys++;

	return true;
}

static void
mbtree_merge(mhead_t *mhead, mchunk_t *mchunk)
{
	mchunk_t   *pchunk;
	mchunk_t   *cchunk;
	mchunk_t   *lchunk;
	mchunk_t   *rchunk;
	int			index, nmove;

	assert(mchunk_is_btree(mchunk));
	if (mchunk->btree.nkeys > MBTREE_NUM_KEYS / 2)
		return;

	/*
	 * when root node has only two child nodes (nkeys==1) and
	 * we tries to delete an item from the child leaf node,
	 * then the child leaf node might be merged due to the
	 * operation.
	 * In this case, we pull up the merged child as a new
	 * root node to reduce depth of the B+tree.
	 */
	if (!mchunk->btree.is_leaf && mchunk->btree.nkeys == 0)
	{
		assert(mchunk->btree.parent == 0);

		cchunk = offset_to_addr(mhead, mchunk->btree.items[0]);
		assert(mchunk_is_btree(cchunk));

		mchunk->btree.is_leaf = cchunk->btree.is_leaf;
		mchunk->btree.nkeys = cchunk->btree.nkeys;
		memcpy(mchunk->btree.keys, cchunk->btree.keys,
			   sizeof(uint32_t) * cchunk->btree.nkeys);
		memcpy(mchunk->btree.items, cchunk->btree.items,
			   sizeof(uint64_t) * (cchunk->btree.nkeys + 1));

		if (!mchunk->btree.is_leaf)
			children_reparent(mhead, mchunk);
	}
	if (mchunk->btree.parent == 0)
		return;

	/*
	 * choose a pair of nodes to be merged.
	 * If @mchunk is on the edge of the parent node, no options
	 * to decide its buddy. Elsewhere, @mchunk is tried to be
	 * merged with either left or right node with smaller number
	 * of elements.
	 */
	pchunk = offset_to_addr(mhead, mchunk->btree.parent);
	assert(mchunk_is_btree(pchunk));

	index = find_child_index(mhead, mchunk);
	if (index == pchunk->btree.nkeys)
		index--;
	else if (index > 0)
	{
		lchunk = offset_to_addr(mhead, pchunk->btree.items[index - 1]);
		rchunk = offset_to_addr(mhead, pchunk->btree.items[index + 1]);
		if (lchunk->btree.nkeys < rchunk->btree.nkeys)
			index--;
	}
	lchunk = offset_to_addr(mhead, pchunk->btree.items[index]);
	rchunk = offset_to_addr(mhead, pchunk->btree.items[index + 1]);
	assert(lchunk->btree.is_leaf == rchunk->btree.is_leaf);

	if (lchunk->btree.is_leaf)
	{
		if (lchunk->btree.nkeys + rchunk->btree.nkeys <= MBTREE_NUM_KEYS)
		{
			/* Move all the items from Right to Left  */
            memcpy(lchunk->btree.keys + lchunk->btree.nkeys, rchunk->btree.keys,
				   sizeof(uint32_t) * rchunk->btree.nkeys);
            memcpy(lchunk->btree.items + lchunk->btree.nkeys, rchunk->btree.items,
				   sizeof(uint64_t) * (rchunk->btree.nkeys + 1));
			lchunk->btree.nkeys += rchunk->btree.nkeys;

			mblock_free(mhead, rchunk);

			/* Remove Right chunk from the parent */
			memmove(pchunk->btree.keys + index,
					pchunk->btree.keys + index + 1,
					sizeof(uint32_t) * (pchunk->btree.nkeys - index));
			memmove(pchunk->btree.items + index + 1,
					pchunk->btree.items + index + 2,
					sizeof(uint64_t) * (pchunk->btree.nkeys - index));
			pchunk->btree.nkeys--;
		}
		else if (lchunk->btree.nkeys > rchunk->btree.nkeys)
		{
			/* Move items from Left to Rigth */
			nmove = (lchunk->btree.nkeys - rchunk->btree.nkeys) / 2;
			if (nmove > 0)
			{
				memmove(rchunk->btree.keys + nmove, rchunk->btree.keys,
						sizeof(uint32_t) * rchunk->btree.nkeys);
				memmove(rchunk->btree.items + nmove, rchunk->btree.items,
						sizeof(uint64_t) * (rchunk->btree.nkeys + 1));
				memmove(rchunk->btree.keys,
						lchunk->btree.keys + lchunk->btree.nkeys - nmove,
						sizeof(uint32_t) * nmove);
				memmove(rchunk->btree.items,
						lchunk->btree.items + lchunk->btree.nkeys - nmove,
						sizeof(uint64_t) * nmove);
				rchunk->btree.nkeys += nmove;
				lchunk->btree.nkeys -= nmove;
				lchunk->btree.items[lchunk->btree.nkeys] = addr_to_offset(mhead, rchunk);

				pchunk->btree.keys[index] = lchunk->btree.keys[lchunk->btree.nkeys - 1];
			}
		}
		else
		{
			/* Move items from Right to Left */
			nmove = (rchunk->btree.nkeys - lchunk->btree.nkeys) / 2;
			if (nmove > 0)
			{
				memmove(lchunk->btree.keys + lchunk->btree.nkeys,
						rchunk->btree.keys,
						sizeof(uint32_t) * nmove);
				memmove(lchunk->btree.items + lchunk->btree.nkeys,
						rchunk->btree.items,
						sizeof(uint64_t) * nmove);
				memmove(rchunk->btree.keys, rchunk->btree.keys + nmove,
						sizeof(uint32_t) * (rchunk->btree.nkeys - nmove));
				memmove(rchunk->btree.items, rchunk->btree.items + nmove,
						sizeof(uint64_t) * (rchunk->btree.nkeys - nmove + 1));
				lchunk->btree.nkeys += nmove;
				rchunk->btree.nkeys -= nmove;
				lchunk->btree.items[lchunk->btree.nkeys] = addr_to_offset(mhead, rchunk);

				pchunk->btree.keys[index] = lchunk->btree.keys[lchunk->btree.nkeys - 1];
			}
		}
	}
	else
	{
		if (lchunk->btree.nkeys + rchunk->btree.nkeys < MBTREE_NUM_KEYS)
		{
			/* Move all the items from Right to Left */
			lchunk->btree.keys[lchunk->btree.nkeys] = pchunk->btree.keys[index];
			memcpy(lchunk->btree.keys + lchunk->btree.nkeys + 1,
				   rchunk->btree.keys,
				   sizeof(uint32_t) * rchunk->btree.nkeys);
			memcpy(lchunk->btree.items + lchunk->btree.nkeys + 1,
				   rchunk->btree.items,
				   sizeof(uint64_t) * (rchunk->btree.nkeys + 1));
			lchunk->btree.nkeys += rchunk->btree.nkeys + 1;

			mblock_free(mhead, rchunk);

			/* Remove Right node from the parent */
			memmove(pchunk->btree.keys + index,
					pchunk->btree.keys + index + 1,
					sizeof(uint32_t) * (pchunk->btree.nkeys - index - 1));
			memmove(pchunk->btree.items + index + 1,
					pchunk->btree.items + index + 2,
					sizeof(uint64_t) * (pchunk->btree.nkeys - index));
			pchunk->btree.nkeys--;

			children_reparent(mhead, lchunk);
		}
		else if (lchunk->btree.nkeys > rchunk->btree.nkeys)
		{
			/* Move items from Left to Right */
			nmove = (lchunk->btree.nkeys - rchunk->btree.nkeys) / 2;
			if (nmove > 0)
			{
				memmove(rchunk->btree.keys + nmove, rchunk->btree.keys,
						sizeof(uint32_t) * rchunk->btree.nkeys);
				memmove(rchunk->btree.items + nmove, rchunk->btree.items,
						sizeof(uint64_t) * (rchunk->btree.nkeys + 1));
				rchunk->btree.keys[nmove - 1] = pchunk->btree.keys[index];
				pchunk->btree.keys[index]
					= lchunk->btree.keys[lchunk->btree.nkeys - nmove];
				memmove(rchunk->btree.keys,
						lchunk->btree.keys + lchunk->btree.nkeys - nmove + 1,
						sizeof(uint64_t) * (nmove - 1));
				memmove(rchunk->btree.items,
						lchunk->btree.items + lchunk->btree.nkeys - nmove,
						sizeof(uint64_t) * nmove);
				rchunk->btree.nkeys += nmove;
				lchunk->btree.nkeys -= nmove;

				children_reparent(mhead, rchunk);
			}
		}
		else
        {
			/* Move items from Right to Left */
			nmove = (rchunk->btree.nkeys - lchunk->btree.nkeys) / 2;
			if (nmove > 0)
			{
				lchunk->btree.keys[lchunk->btree.nkeys] = pchunk->btree.keys[index];
				pchunk->btree.keys[index] = rchunk->btree.keys[nmove - 1];

				memmove(lchunk->btree.keys + lchunk->btree.nkeys + 1,
						rchunk->btree.keys,
						sizeof(uint32_t) * (nmove - 1));
				memmove(lchunk->btree.items + lchunk->btree.nkeys + 1,
						rchunk->btree.items,
						sizeof(uint64_t) * nmove);
				memmove(rchunk->btree.keys, rchunk->btree.keys + nmove,
						sizeof(uint32_t) * (rchunk->btree.nkeys - nmove));
				memmove(rchunk->btree.items, rchunk->btree.items + nmove,
						sizeof(uint64_t) * (rchunk->btree.nkeys - nmove + 1));
				lchunk->btree.nkeys += nmove;
				rchunk->btree.nkeys -= nmove;

				children_reparent(mhead, lchunk);
			}
		}
	}
}

static bool
do_mbtree_delete(mhead_t *mhead, mchunk_t *mchunk,
				 uint32_t key, uint64_t item)
{
	mchunk_t   *cchunk;
	int			index;

	assert(mchunk_is_btree(mchunk));

	/*
	 * If @mchunk is not a leaf node, we walk down to the next level.
	 */
	if (!mchunk->btree.is_leaf)
	{
		index = find_key_index(mchunk, key);

		cchunk = offset_to_addr(mhead, mchunk->btree.items[index]);

		if (!do_mbtree_delete(mhead, cchunk, key, item))
			return false;

		mbtree_merge(mhead, mchunk);

		return true;
	}

	/*
	 * Leaf node to be removed from
	 */
	index = find_key_index(mchunk, key);
	while (mchunk->btree.keys[index] == key)
	{
		if (mchunk->btree.items[index] == item)
		{
/*
			fprintf(stderr,
					"delete hkey=0x%08" PRIx32 ", "
					"hitem=0x%08" PRIx64 "\n", key, item);
*/

			memmove(mchunk->btree.keys + index,
					mchunk->btree.keys + index + 1,
					sizeof(uint32_t) * (mchunk->btree.nkeys - index - 1));
			memmove(mchunk->btree.items + index,
					mchunk->btree.items + index + 1,
					sizeof(uint64_t) * (mchunk->btree.nkeys - index));
			mchunk->btree.nkeys--;

			mbtree_merge(mhead, mchunk);

			return true;
		}
		if (++index == mchunk->btree.nkeys)
		{
			if (mchunk->btree.items[index] == 0)
				break;

			mchunk = offset_to_addr(mhead, mchunk->btree.items[index]);
			index = 0;

			assert(mchunk_is_btree(mchunk));
		}
	}
	return false;	/* not found */
}

bool
mbtree_delete(mhead_t *mhead, uint32_t key, uint64_t item)
{
	mchunk_t   *mchunk = (mchunk_t *)mhead->super_block;

	/* special case handling, if root node has no entry. */
	assert(mchunk_is_btree(mchunk));
	if (mchunk->btree.is_leaf && mchunk->btree.nkeys == 0)
		return false;

	return do_mbtree_delete(mhead, mchunk, key, item);
}

static void
mbtree_dump_chunk(mhead_t *mhead, mchunk_t *mchunk, int level)
{
	mchunk_t   *cchunk;
	int			i;

	if (mchunk->btree.is_leaf)
	{
		printf("%*sLEAF (0x%" PRIx64 ", nkeys=%u, parent=0x%" PRIx64 ") {\n",
			   level, "",
			   addr_to_offset(mhead, mchunk),
			   mchunk->btree.nkeys,
			   mchunk->btree.parent);
		for (i = 0; i < mchunk->btree.nkeys; i++)
		{
			printf("%*s[%d] key=%" PRIu32 ", item=%" PRIu64 "\n",
				   level + 2, "", i,
				   mchunk->btree.keys[i],
				   mchunk->btree.items[i]);
		}
		printf("%*s} next=0x%" PRIx64 "\n",
			   level, "",
			   mchunk->btree.items[mchunk->btree.nkeys]);
	}
	else
	{
		printf("%*sNODE (0x%" PRIx64 ", nkeys=%d, parent=0x%" PRIx64 ") {\n",
			   level, "",
			   addr_to_offset(mhead, mchunk),
			   mchunk->btree.nkeys,
			   mchunk->btree.parent);
		for (i = 0; i <= mchunk->btree.nkeys; i++)
		{
			cchunk = offset_to_addr(mhead, mchunk->btree.items[i]);
			mbtree_dump_chunk(mhead, cchunk, level+2);
			if (i < mchunk->btree.nkeys)
				printf("%*s[KEY=%" PRIu32 "]\n",
					   level + 2, "", mchunk->btree.keys[i]);
		}
		printf("%*s}\n", level, "");
	}
}

void
mbtree_dump(mhead_t *mhead)
{
	mchunk_t   *mchunk = (mchunk_t *) mhead->super_block;

	mbtree_dump_chunk(mhead, mchunk, 0);
}

mhead_t *
mbtree_open(int fdesc, size_t block_size)
{
	mhead_t	   *mhead;
	mchunk_t   *mchunk;

	mhead = mblock_map(fdesc, block_size, sizeof(mchunk_t));
	if (!mhead)
		return NULL;

	mchunk = (mchunk_t *)mhead->super_block;
	if (mchunk->tag != MCHUNK_TAG_BTREE ||
		mchunk->magic != mchunk_magic(mhead, mchunk))
	{
		/*
		 * If block is not initialized yet, set up root node
		 * on the superblock.
		 */
		mchunk->tag = MCHUNK_TAG_BTREE;
		mchunk->mclass = 0;	/* dummy */
		mchunk->magic = mchunk_magic(mhead, mchunk);
		mchunk->btree.parent = 0;
		mchunk->btree.is_leaf = true;
		mchunk->btree.nkeys = 0;
		memset(mchunk->btree.keys, 0, sizeof(mchunk->btree.keys));
		memset(mchunk->btree.items, 0, sizeof(mchunk->btree.items));
	}
	return mhead;
}

void
mbtree_close(mhead_t *mhead)
{
	mblock_unmap(mhead);
}

#if 1
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

	handle = mbtree_open(fd, stbuf.st_size);
	if (!handle)
	{
		printf("failed to init mblock\n");
		return 1;
	}

	if (argc == 4 && strcmp(argv[2], "get") == 0)
	{
		mbtree_scan     scan;
		uint32_t        key;

		key = atol(argv[3]);
		memset(&scan, 0, sizeof(scan));
		scan.key = key;
		while (mbtree_lookup(handle, &scan) && scan.key == key)
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
		return 0;
	}

usage:
	printf("usage: %s <filename> get <key>\n", argv[0]);
	printf("       %s <filename> ins <key> <value>\n", argv[0]);
	printf("       %s <filename> del <key> <value>\n", argv[0]);

	return 1;
}
#endif
