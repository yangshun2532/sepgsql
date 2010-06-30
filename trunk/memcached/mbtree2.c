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
	uint32_t	crc32;		/* crc code of fixed length area */
	uint16_t	flags;		/* see MBCHUNK_FLAG_* */
	uint16_t	nkeys;		/* length of key */
	uint32_t	ndata;		/* length of value */	
	uint32_t	exptime;	/* exptime from unix epoch, or 0 */
	uint8_t		data[0];
};
typedef struct mbtree_chunk mchunk_t;

#define MBCHUNK_FLAG_CLASSES	0x007f
#define MBCHUNK_FLAG_ACTIVE		0x0080

#define mchunk_is_active(mc)	((mc)->flags & MBCHUNK_FLAG_ACTIVE)
#define mchunk_get_class(mc)	((mc)->flags & MBCHUNK_FLAG_CLASSES)
#define mchunk_get_key(mc)		((mc)->data)
#define mchunk_get_data(mc)		((mc)->data + (mc)->nkeys)

/*
 * mbtree_item
 *
 * On local memory image of the item
 */
struct mbtree_item {
	int			refcount;
	uint64_t	cas;
	mb_chunk_t *chunk;
};
typedef struct mbtree_item mb_item_t;

/*
 * mbtree_node
 *
 * Node/Leaf of the B+Tree index structure
 */
#define MBNODE_NUM_KEYS		6
struct mbtree_node {
	struct mbtree_node *parent;
	uint16_t	nkeys;
	bool		is_leaf;
	uint32_t	keys[MBNODE_NUM_KEYS];
	void	   *items[MBNODE_NUM_KEYS + 1];
};
typedef struct mbtree_node mnode_t;

struct mbtree_head {
	/* B+tree structures */
	mnode_t	   *root;

	/* mmap()'ed region */
	size_t		block_size;
	void	   *block_data;



	/* statical information */

};
typedef struct mbtree_head mhead_t;








/*
 *
 *
 *
 */
void *
mbtree_map(int fdesc, size_t block_size)
{




}

void
mbtree_unmap(void *handle)
{
	mbtree_head	   *mhead = handle;


}
