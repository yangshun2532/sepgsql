/*
 * mbtree.c
 *
 * B-plus Tree routines
 */


static int
find_key_index(mchunk_t *mchunk, uint32_t key)
{
	int		min = 0;
	int		max = mchunk->nkeys;
	int		index;

	assert(mchunk->tag == MCHUNK_TAG_BTREE);
	if (mchunk->btree.nkeys == 0)
	{
		assert(mchunk->parent == 0);
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
		if (pchunk->items[index] == offset)
			return index;
	}
	assert(false);
}

static void
children_reparent(mhead_t *mhead, mchunk_t *mchunk)
{
	uint64_t	parent = addr_to_offset(mchunk);
	int			index;

	for (index = 0; index <= mchunk->btree.nkeys; index++)
	{
		mchunk_t *cchunk = offset_to_addr(mhead, mchunk->btree.items[index]);

		cchunk->btree.parent = parent;
	}
}

bool
mbtree_lookup(mhead_t *mhead, uint32_t key, mbtree_scan *scan)
{
	mchunk_t   *mchunk;
	int			index;

	if (scan->mnode == 0 || scan->key != key)
	{
		mchunk = offset_to_addr(mhead, scan->mnode);
		assert(mchunk->tag == MCHUNK_TAG_BTREE);

		while (!mchunk->btree.is_leaf)
		{
			index = find_key_index(mchunk, key);

			mchunk = offset_to_addr(mhead, mchunk->btree.items[index]);
		}
		index = find_key_index(mchunk, key);
		if (mchunk->btree.keys[index] == key)
		{
			scan->mnode = addr_to_offset(mhead, mchunk);
			scan->index = index;
			scan->key = key;
			scan->item = mnode->items[index];

			return true;
		}
	}
	else
	{
		mchunk = offset_to_addr(mhead, scan->mnode);
		index = scan->index + 1;

		if (index == mchunk->nkeys)
		{
			mchunk = offset_to_addr(mhead, mchunk->btree.items[index]);
			index = 0;
		}
		if (mchunk->btree.keys[index] == scan->key)
		{
			scan->mnode = addr_to_offset(mhead, mchunk);
			scan->index = index;
			scan->item = mchunk->btree.items[index];

			return true;
		}
	}
	return false;
}

static bool
mbtree_split(mhead_t *mhead, mchunk_t *mchunk)
{
	if (!mchunk->parent)
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
			rchunk->btree.nkeys = mchunk->nkeys - xsect;
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

			pkey = mnode->keys[xsect];
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
		pchunk = offset_to_addr(mhead, mchunk->parent);
		if (pchunk->btree.nkeys == MBTREE_NUM_KEYS)
        {
			if (!mbtree_split(mhead, pchunk))
				return false;
			pchunk = offset_to_addr(mhead, mchunk->parent);
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

			pkey = mchunk->btree.keys[mnode->nkeys - 1];
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

		mchunk = offset_to_addr(mhead, mchunk->items[index]);
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

bool
mbtree_delete(mhead_t *mhead, uint32_t key, uint64_t item)
{}

void
mbtree_dump(mhead_t *mhead)
{}

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
		mchunk->magic != mchunk_magic(mchunk))
	{
		/*
		 * If block is not initialized yet, set up root node
		 * on the superblock.
		 */
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
{}
