/*
 * mbtree.c
 *
 * mmap() based B+ tree indexes
 *
 * 
 */

#define MBTREE_VERSION			0x20100701

/*
 * mbtree_chunk
 *
 * On disk image of the item
 */
struct mbtree_chunk {
	uint32_t	crc32;		/* crc32 code */
	uint16_t	flags;		/* see MBCHUNK_FLAG_* */
	uint16_t	key_len;	/* length of key */
	uint32_t	data_len;	/* length of value */	
	uint32_t	exptime;	/* exptime from unix epoch, or 0 */
	uint8_t		data[0];
};
typedef struct mbtree_chunk mchunk_t;

#define MCHUNK_FLAG_CLASSES		0x007f
#define MCHUNK_FLAG_ACTIVE		0x0080
#define MCHUNK_CRC32_LENGTH		(offset_of(mchunk_t, data) - offset_of(mchunk_t, flags))

#define mchunk_is_active(mc)	((mc)->flags & MCHUNK_FLAG_ACTIVE)
#define mchunk_get_class(mc)	((mc)->flags & MCHUNK_FLAG_CLASSES)
#define mchunk_get_key(mc)		((mc)->data)
#define mchunk_get_data(mc)		((mc)->data + (mc)->nkeys)

/*
 * mbtree_item
 *
 * On local memory image of the item
 */
struct mbtree_item {
	struct mbtree_item *next;	/* link in free_list */
	uint32_t	hkey;			/* key of B+tree */
	int			refcount;		/* reference count */
	uint64_t	cas;			/* compare-and-set */
	mb_chunk_t *chunk;
};
typedef struct mbtree_item mitem_t;

/*
 * mbtree_node
 *
 * Node/Leaf of the B+Tree index structure
 */
#define MBNODE_NUM_KEYS		6
struct mbtree_node {
	struct mbtree_node *parent;
	uint16_t	nkeys;
	bool		leaf;
	uint32_t	keys[MBNODE_NUM_KEYS];
	void	   *items[MBNODE_NUM_KEYS + 1];
};
typedef struct mbtree_node mnode_t;

/*
 * mbtree_head
 *
 */
#define MBLOCK_MIN_BITS		7	/* 128bytes */
#define MBLOCK_MAX_BITS		25	/* 32MB */
#define MBLOCK_MIN_SIZE		(1<<MBLOCK_MIN_BITS)
#define MBLOCK_MAX_BITS		(1<<MBLOCK_MAX_BITS)

struct mbtree_head {
	/* B+tree structures */
	mnode_t	   *root;

	/* Block management */
	size_t		block_size;
	void	   *block_data;
	mb_item_t  *free_list[MBLOCK_MAX_BITS + 1];

	/* statical information */
	uint32_t	num_free[MBLOCK_MAX_BITS + 1];
	uint32_t	num_actives[MBLOCK_MAX_BITS + 1];

	uint32_t	(*hash_fn)(const void *, size_t, uint32_t);
};
typedef struct mbtree_head mhead_t;

#define offset_to_addr(mhead,offset)			\
	((void *)(((unsigned long)(mhead)->block_data) + offset))
#define addr_to_offset(mhead,addr)				\
	((uint64_t)(((unsigned long)(addr)) - ((unsigned long)((mhead)->block_data))))
#define offset_of(type, member)					\
	((unsigned long) &((type *)0)->member)

static int
find_key_index(mnode_t *mnode, uint32_t hkey)
{
	int		min = 0;
	int		max = mnode->nkeys;
	int		index;

	if (mnode->nkeys == 0)
		return 0;

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
find_child_index(mnode_t *pnode, mnode_t *mnode)
{
	//int		index = find_key_index(pnode, mnode->keys[0]);
	int			index;

	assert(!pnode->leaf);
	assert(pnode == mnode->parent);

	for (index = 0; index <= pnode->nkeys; index++)
	{
		if (pnode->items[index] == mnode)
			return index;
	}
	assert(false);
}

static void
children_reparent(mnode_t *mnode)
{
	mnode_t	   *cnode;
	int			index;

	assert(!mnode->leaf);

	for (index = 0; index <= mnode->nkeys; index++)
	{
		cnode = mnode->items[index];

		cnode->parent = mnode;
	}
}

static bool
mbtree_split(mhead_t *mhead, mnode_t *mnode)
{
	if (!mnode->parent)
	{
		mnode_t	   *lnode;
		mnode_t	   *rnode;
		uint32_t	pkey;
		int			xsect;

		lnode = malloc(sizeof(mnode_t));
		if (!lnode)
			return false;

		rnode = malloc(sizeof(mnode_t));
		if (!rnode)
		{
			free(lnode);
			return false;
		}

		lnode->parent = rnode->parent = mnode;
		lnode->leaf = rnode->leaf = mnode->leaf;

		xsect = mnode->nkeys / 2;
		if (mnode->leaf)
		{
			/* copy smaller half to left leaf */
			memcpy(lnode->keys, mnode->keys,
				   sizeof(uint32_t) * xsect);
			memcpy(lnode->items, mnode->items,
				   sizeof(void *) * xsect);
			llnode->nkeys = xsect;
			lnode->items[lnode->nkeys] = rnode;

			/* copy larger half to right leaf */
			memcpy(rnode->keys, mnode->keys + xsect,
				   sizeof(uint32_t) * (mnode->nkeys - xsect));
			memcpy(rnode->items, mnode->items + xsect,
				   sizeof(void *) *  (mnode->nkeys - xsect));
			rnode->nkeys = mnode->nkeys - xsect;
			rnode->items[rnode->nkeys] = NULL;

			pkey = lnode->keys[lnode->nkeys - 1];
		}
		else
		{
			/* copy smaller half to left node */
			memcpy(lnode->keys, mnode->keys,
				   sizeof(uint32_t) * xsect);
			memcpy(lnode->items, mnode->items,
				   sizeof(void *) * (xsect + 1));
			lnode->nkeys = xsect;
			children_reparent(lnode);

			/* copy larger half to right node */
			memcpy(rnode->keys, mnode->keys + xsect + 1,
				   sizeof(uint32_t) * (mnode->nkeys - xsect - 1));
			memcpy(rnode->items, mnode->items + xsect + 1,
				   sizeof(void *) * (mnode->nkeys - xsect));
			rnode->nkeys = mnode->nkeys - xsect - 1;
            children_reparent(rnode);

			pkey = mnode->keys[xsect];
		}
		/* fix up root node */
		mnode->leaf = false;
		mnode->nkeys = 1;
		mnode->keys[0] = pkey;
		mnode->items[0] = lnode;
		mnode->items[1] = rnode;
	}
	else
	{
		mnode_t	   *pnode = mnode->parent;
		mnode_t	   *nnode;
		uint32_t	pkey;
		int			xsect, index;

		nnode = malloc(sizeof(mnode_t));
		if (!nnode)
			return false;

		if (pnode->nkeys == MBTREE_NUM_KEYS)
		{
			if (!mbtree_split(mhead, pnode))
			{
				free(nnode);
				return false;
			}
			/*
			 * mnode->parent might be reparent during split
			 */
			pnode = mnode->parent;
		}
		nnode->leaf = mnode->leaf;
		nnode->parent = mnode->parent;

		xsect = mnode->nkeys / 2;
		if (mnode->leaf)
		{
			/* copy larger half of the leaf */
			memcpy(nnode->keys, mnode->keys + xsect,
				   sizeof(uint32_t) * (mnode->nkeys - xsect));
			memcpy(nnode->items, mnode->items + xsect,
				   sizeof(void *) * (mnode->nkeys - xsect + 1));
			nnode->nkeys = mnode->nkeys - xsect;
			mnode->nkeys = xsect;
			mnode->items[xsect] = nnode;

			pkey = mnode->keys[mnode->nkeys - 1];
		}
		else
		{
			/* copy larger half of the node */
			memcpy(nnode->keys, mnode->keys + xsect + 1,
				   sizeof(uint32_t) * (mnode->nkeys - (xsect + 1)));
			memcpy(nnode->items, mnode->items + xsect + 1,
				   sizeof(void *) * (mnode->nkeys - xsect));
			nnode->nkeys = mnode->nkeys - (xsect + 1);
			mnode->nkeys = xsect;

			children_reparent(nnode);

            pkey = mnode->keys[xsect];
		}
		/* insert nnode into pnode next to mnode*/
		index = find_child_index(pnode, mnode);

		memmove(pnode->keys + index + 1, pnode->keys + index,
				sizeof(uint32_t) * (pnode->nkeys - index));
		memmove(pnode->items + index + 2, pnode->items + index + 1,
				sizeof(void *) * (pnode->nkeys - index));
		pnode->keys[index] = pkey;
		pnode->items[index + 1] = nnode;
		pnode->nkeys++;
	}
	return true;
}

static void
mbtree_merge(mhead_t *mhead, mnode_t *mnode)
{
	mnode_t	   *pnode = mnode->parent;
	mnode_t	   *cnode;
	mnode_t	   *lnode;
	mnode_t	   *rnode;
	int			index, nmove;

	/* No need to merge this node with enough entities */
	if (mnode->nkeys > MBTREE_NUM_KEYS / 2)
		return;

	/*
	 * If root node (not leaf) has two children them these are
	 * merged into one, we don't need to keep the root node.
	 * So, we pull up the child node as a new root to reduce
	 * depth of the B+tree.
	 */
	if (mnode->nkeys == 0 && !mnode->leaf)
	{
		assert(!parent);
		assert(mhead->root == mnode);

		cnode = mnode->items[0];
		cnode->parent = NULL;
		mhead->root = cnode;

		free(mnode);

		return;
	}
	if (!mnode->parent)
		return;

	/*
	 * Select two nodes to be merged.
	 */
	index = find_child_index(pnode, mnode);
	if (index == pnode->nkeys)
		index--;
	else if (index > 0)
	{
		lnode = pnode->items[index - 1];
		rnode = pnode->items[index + 1];
		if (lnode->nkeys < rnode->nkeys)
			index--;
	}
	lnode = pnode->items[index];
	rnode = pnode->items[index + 1];
	assert(lnode->leaf == rnode->leaf);

	if (lnode->leaf)
	{
		if (lnode->nkeys + rnode->nkeys <= MBTREE_NUM_KEYS)
		{
			/* Try to merge two leafs into one */
			memcpy(lnode->keys + lnode->nkeys, rnode->keys,
				   sizeof(uint32_t) * rnode->nkeys);
			memcpy(lnode->items + lnode->nkeys, rnode->items,
				   sizeof(void *) * (rnode->nkeys + 1));
			lnode->nkeys += rnode->nkeys;

			free(rnode);

			/* Remove rnode from pnode */
			memmove(pnode->keys + index, pnode->keys + index + 1,
					sizeof(uint32_t) * (pnode->nkeys - index));
			memmove(pnode->items + index + 1, pnode->items + index + 2,
					sizeof(void *) * (pnode->nkeys - index));
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
						sizeof(void *) * (rnode->nkeys + 1));
				memmove(rnode->keys, lnode->keys + lnode->nkeys - nmove,
						sizeof(uint32_t) * nmove);
				memmove(rnode->items, lnode->items + lnode->nkeys - nmove,
						sizeof(void *) * nmove);
				rnode->nkeys += nmove;
				lnode->nkeys -= nmove;
				lnode->items[lnode->nkeys] = rnode;

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
						sizeof(void *) * nmove);
				memmove(rnode->keys, rnode->keys + nmove,
						sizeof(uint32_t) * (rnode->nkeys - nmove));
				memmove(rnode->items, rnode->items + nmove,
						sizeof(void *) * (rnode->nkeys - nmove + 1));
				lnode->nkeys += nmove;
				rnode->nkeys -= nmove;
				lnode->items[lnode->nkeys] = rnode;

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
				   sizeof(void *) * (rnode->nkeys + 1));
			lnode->nkeys += rnode->nkeys + 1;

			free(rnode);

			/* Remove rnode from pnode */
			memmove(pnode->keys + index + 1, pnode->keys + index + 2,
					sizeof(uint32_t) * (pnode->nkeys - index - 1));
			memmove(pnode->items + index + 1, pnode->items + index + 2,
					sizeof(void *) * (pnode->nkeys - index));
            pnode->nkeys--;

			children_reparent(lnode);
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
						sizeof(void *) * (rnode->nkeys + 1));
				rnode->keys[nmove - 1] = pnode->keys[index];
				pnode->keys[index] = lnode->keys[lnode->nkeys - nmove];
				memmove(rnode->keys, lnode->keys + lnode->nkeys - nmove + 1,
						sizeof(uint64_t) * (nmove - 1));
				memmove(rnode->items, lnode->items + lnode->nkeys - nmove,
						sizeof(void *) * nmove);
				rnode->nkeys += nmove;
				lnode->nkeys -= nmove;

				children_reparent(rnode);
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
						sizeof(void *) * nmove);
				memmove(rnode->keys, rnode->keys + nmove,
						sizeof(uint32_t) * (rnode->nkeys - nmove));
				memmove(rnode->items, rnode->items + nmove,
						sizeof(void *) * (rnode->nkeys - nmove + 1));
				lnode->nkeys += nmove;
				rnode->nkeys -= nmove;

				children_reparent(lnode);
			}
		}
	}
}

static bool
mbtree_insert(mhead_t *mhead, mitem_t *mitem)
{
	mnode_t	   *mnode;
	mchunk_t   *mchunk = mitem->mchunk;
	int			index;

	assert(mitem->hkey == mhead->hash_fn(mchunk->data,
										 mchunk->key_len,
										 MBTREE_SEED));
retry:
	mnode = mhead->root;
	while (!mnode->leaf)
	{
		index = find_key_index(mnode, mitem->hkey);

		mnode = mnode->items[index];
	}

	/*
	 * if the leaf node is already fulled-up, we try to
	 * divide it into two nodes
	 */
	if (mnode->nkeys == MBNODE_NUM_KEYS)
	{
		if (!mbtree_split(mhead, mnode))
			return false;

		goto retry;
	}
	index = find_key_index(mnode, mitem->hkey);

	/*
	 * Insert a mitem object into B+tree
	 */
	memmove(mnode->keys + index + 1, mnode->keys + index,
			sizeof(uint32_t) * (mnode->nkeys - index));
	memmove(mnode->items + index + 1, mnode->items + index,
			sizeof(void *) * (mnode->nkeys - index + 1));
	mnode->keys[index] = hkey;
	mnode->items[index] = mitem;
	mnode->nkeys++;

	return true;
}

static bool
mbtree_split_chunk(mhead_t *mhead, int mclass)
{
	mitem_t	   *mitem1;
	mitem_t	   *mitem2;
	mchunk_t   *mchunk;
	uint64_t	offset;

	assert(mclass > MBLOCK_MIN_BITS && mclass <= MBLOCK_MAX_BITS);

	mitem1 = malloc(sizeof(mitem_t));
	if (!mitem1)
		return false;

	if (mhead->free_list[mclass] == NULL)
	{
		if (mclass == MBLOCK_MAX_BITS)
		{
			free(mitem1);
			return false;
		}
		else if (!mbtree_split_chunk(mhead, mclass + 1))
		{
			free(mitem1);
			return false;
		}
	}
	/* detach an item from freelist */
	mitem2 = mhead->free_list[mclass];
	mhead->free_list[mclass] = mitem2->next;
	mitem2->next = NULL;
	assert(mclass == mchunk_get_class(mitem2) && !mchunk_is_active(mitem2));

	mclass--;
	mchunk = mitem2->chunk;
	memset(mchunk, 0, sizeof(mchunk_t));
	mchunk->flags = (1<<mclass);
	mchunk->crc32 = crc32(&mchunk->flags, MCHUNK_CRC32_LENGTH);

	mchunk = (mchunk_t *)((((unsigned long)mitem2->chunk) + (1<<mclass)));
	memset(mchunk, 0, sizeof(mchunk_t));
	mchunk->flags = (1<<mclass);
	mchunk->crc32 = crc32(&mchunk->flags, MCHUNK_CRC32_LENGTH);
	mitem1->chunk = mchunk;

	mitem1->next = mitem2;
	mitem2->next = mhead->free_list[mclass];
	mhead->free_list[mclass] = mitem1;

	return true;
}

void *
mbtree_alloc(void *handle,
			 const void *key,
			 const uint16_t key_len,
			 const uint32_t data_len,
			 const rel_time_t exptime)
{
	mhead_t	   *mhead = handle;
	mitem_t	   *mitem;
	mchunk_t   *mchunk;
	int			mclass;

	mclass = fls64(sizeof(mchunk_t) + key_len + data_len);
	if (mclass > MBLOCK_MAX_BITS)
		return NULL;
	if (mclass < MBLOCK_MIN_BITS)
		mclass = MBLOCK_MIN_BITS;

	if (!mhead->free_list[mclass])
	{
		if (!mbtree_split_chunk(mhead, mclass + 1))
			return NULL;
	}
	assert(mhead->free_list[mclass] != NULL);

	mitem = mhead->free_list[mclass];
	mhead->free_list[mclass] = mitem->next;
	mitem->next = NULL;
	mitem->hkey = mhead->hash_fh(key, key_len, MBTREE_MAGIC);
	mitem->refcount = 0;
	mitem->cas = 0;

	mchunk = mitem->chunk;
	mchunk->flags = (mclass & MCHUNK_FLAG_CLASSES) | MCHUNK_FLAG_ACTIVE;
	mchunk->key_len = key_len;
	mchunk->data_len = data_len;
	mchunk->exptime = exptime;
	memcpy(mchunk->data, key, key_len);
	mchunk->crc32 = crc32(&mchunk->flags, MCHUNK_CRC32_LENGTH);

	if (!mbtree_insert(mhead, mitem))
	{
		/* todo free, and merge mchunks */
		
	}
	return (void *)mitem;
}

static bool
mbtree_delete(mhead_t *mhead, mitem_t *mitem)
{
	mnode_t	   *mnode;
	mchunk_t   *mchunk = mitem->mchunk;
	uint32_t	hkey;
	int			index;

	hkey = mhead->hash_fn(mchunk->data,
						  mchunk->key_len +
						  mchunk->data_len,
						  MBTREE_SEED);
	mnode = mhead->root;
	while (!mnode->leaf)
	{
		index = find_key_index(mnode, hkey);

		mnode = mnode->items[index];
	}
	/*
	 * Only when root node, it may not have any entities.
	 */
	if (mnode->nkeys == 0)
	{
		assert(!mnode->super);
		return false;
	}

	/*
	 * Leaf node to be removed
	 */
	index = find_key_index(mnode, hkey);
	while (mnode->keys[index] == hkey)
	{
		if (mnode->items[index] == mitem)
		{
			memmove(mnode->keys + index, mnode->keys + index + 1,
					sizeof(uint32_t) * (mnode->nkeys - index - 1));
			memmove(mnode->items + index, mnode->items + index + 1,
					sizeof(void *) * (mnode->nkeys - index));
			mnode->nkeys--;

			mbtree_merge(mhead, mnode);

			return true;
		}
		if (++index == mnode->nkeys)
		{
			if (!mnode->items[index])
				break;
			mnode = mnode->items[index];
			index = 0;
		}
	}
	return false;	/* not found */
}

static void
mbtree_merge_chunk(mhead_t *mhead, mitem_t *mitem)
{}

void
mbtree_free(mitem_t *mitem)
{}

void
mbtree_reset(void *handle)
{}

/*
 * mbtree_dump
 */
void
mbtree_dump(void *handle)
{
	mhead_t	   *mhead = handle;

}

/*
 * mbtree_map
 *
 *
 */
void *
mbtree_map(int fdesc, size_t block_size,
		   uint32_t (*hash_fn)(const void *, size_t, uint32_t))
{
	mhead_t	   *mhead;
	mitem_t	   *mitem;
	mchunk_t   *mchunk;
	uint64_t	offset;

	mhead = malloc(sizeof(mhead_t));
	if (!mhead)
		return NULL;

	mhead->hash_fn = hash_fn;
	mhead->block_size = block_size;
	mhead->block_data = mmap(NULL, block_size,
							 PROT_READ | PROT_WRITE,
							 fdesc < 0 ? MAP_ANONYMOUS | MAP_PRIVATE : MAP_SHARED,
							 fdesc, 0);
	if (mhead->block_data == MAP_FAILED)
	{
		free(mhead);
		return NULL;
	}

	/*
	 * Initialization
	 */
	offset = 0;
	while (offset < block_size)
	{
		uint32_t	crc;
		int			mclass;

		mchunk = offset_to_addr(mhead, offset);
		if (mchunk->crc32 == crc32(&mhead->flags, MCHUNK_CRC32_LENGTH))
		{
			mclass = mchunk_get_class(mchunk);

			if ((offset & ((1<<mclass) - 1)) == 0)
			{
				mitem = malloc(sizeof(mitem_t));
				if (!mitem)
					goto error;
				memset(mitem, 0, sizeof(mitem_t));

				mitem->hash = mhead->hash_fn(mchunk->data,
											 mchunk->nkeys,
											 MBTREE_MAGIC);
				if (!mbtree_insert(mhead, mitem))
					goto error;

				offset += (1<<mclass);
				continue;
			}
		}
		/*
		 * Elsewhere, chunk will be chained to free_list
		 */
		mclass = ffs64(offset) - 1;

		memset(&mchunk->flags, 0, MCHUNK_CRC_LENGTH);
		mchunk->flags = mclass;
		mchunk->crc32 = crc32(&mhead->flags, MCHUNK_CRC_LENGTH);

		mitem = malloc(sizeof(mitem_t));
		if (!mitem)
			goto error;
		memset(mitem, 0, sizeof(mitem_t));

		mitem->chunk = mchunk;

		mitem->next = mhead->free_list[mclass];
		mhead->free_list[mclass] = mitem;

		offset += (1<<mclass);
	}
	return mhead;

error:
	return mhead;
}

void
mbtree_unmap(void *handle)
{
	mbtree_head	   *mhead = handle;

	munmap(mhead->block_data, mhead->block_size);

	free(mhead);
}
