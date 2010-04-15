/*
 * mbtree.c
 *
 * mmap based B-plus tree routeines.
 *
 *
 *
 */
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




uint64_t
mbtree_lookup(void *handle, void *mbroot, uint32_t key, mbtree_state *state)
{
}

uint64_t
mbtree_lookup_next(void *handle, void *mbroot, mbtree_state *state)
{
}

bool
mbtree_insert(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_item	   *mbitem = mbroot;

	if ((mbitem->flags & MBTREE_FLAGS_IS_LEAF) == 0)
	{
		
		
	}




}

bool
mbtree_delete(void *handle, void *mbroot, uint32_t key, uint64_t item)
{
	mbtree_item	   *mbroot = mbroot;


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
