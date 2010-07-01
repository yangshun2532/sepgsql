/*
 * selinux_engine.h
 *
 * Header file of the selinux engine module
 *
 *
 */
#ifndef SELINUX_ENGINE_H
#define SELINUX_ENGINE_H

/*
 * mlist_t - dual linked list on the memory block
 */
typedef struct {
	uint64_t	prev;
	uint64_t	next;
} mlist_t;

/*
 * mchunk_t
 *
 * memory block chunk for various kind of data block
 */
#define MCHUNK_TAG_FREE		0
#define MCHUNK_TAG_ITEM		1
#define MCHUNK_TAG_BTREE	2
#define MCHUNK_TAG_LABEL	3

typedef struct {
	uint16_t	magic;
	uint8_t		mclass;
	uint8_t		tag;
	union {
		/* MCHUNK_TAG_FREE */
		struct {
			mlist_t		list;
		} free;
		/* MCHUNK_TAG_ITEM */
		struct {
			uint16_t	flags;
			uint16_t	keylen;
			uint32_t	datalen;
			uint32_t	exptime;
			uint8_t		data[0];
		} item;
		/* MCHUNK_TAG_BTREE */
		struct {
#define MBTREE_NUM_KEYS		7
			uint64_t	parent;
			uint8_t		is_leaf;
			uint32_t	keys[MBTREE_NUM_KEYS];
			uint64_t	items[MBTREE_NUM_KEYS + 1];
		} btree;
		/* MCHUNK_TAG_LABEL */
		struct {
			uint32_t	refcount;
			uint8_t		label[0];
		} label;
	};
} mchunk_t;

/*
 * mbtree.c - mmap based B-plus tree index
 */
typedef struct
{
	/* internal pointer, don't touch! */
	uint64_t	mnode;
	int			index;

	/* fetched key&item pair */
	uint32_t	key;
	uint64_t	item;
} mbtree_scan;

extern bool  mbtree_lookup(void *handle, uint32_t key, mbtree_scan *scan);
extern void  mbtree_dump(void *handle);
extern bool  mbtree_insert(void *handle, uint32_t key, uint64_t item);
extern bool  mbtree_delete(void *handle, uint32_t key, uint64_t item);
extern void *mbtree_init(int fdesc, size_t block_size);

/*
 * mblock.c - memory block management
 */
extern mchunk_t *mblock_alloc(void *handle, uint8_t tag, size_t size);
extern void      mblock_free(void *handle, mchunk_t *mchunk);
extern void      mblock_dump(void *handle);
extern void      mblock_reset(void *handle);
extern void     *mblock_map(int fdesc, size_t block_size, size_t super_size);
extern void      mblock_unmap(void *handle);

/*
 * ffs64 - returns first (smallest) bit of the value
 */
static inline int
ffs64(uint64_t value)
{
	int		ret = 1;

	if (!value)
		return 0;
	if (!(value & 0xffffffff))
	{
		value >>= 32;
		ret += 32;
	}
	if (!(value & 0x0000ffff))
	{
		value >>= 16;
		ret += 16;
	}
	if (!(value & 0x000000ff))
	{
		value >>= 8;
		ret += 8;
	}
	if (!(value & 0x0000000f))
	{
		value >>= 4;
		ret += 4;
	}
	if (!(value & 0x00000003))
	{
		value >>= 2;
		ret += 2;
	}
	if (!(value & 0x00000001))
	{
		value >>= 1;
		ret += 1;
	}
	return ret;
}

/*
 * fls64 - returns last (biggest) bit of the value
 */
static inline int
fls64(uint64_t value)
{
	int		ret = 1;

	if (!value)
		return 0;
	if (value & 0xffffffff00000000)
	{
		value >>= 32;
		ret += 32;
	}
	if (value & 0xffff0000)
	{
		value >>= 16;
		ret += 16;
	}
	if (value & 0xff00)
	{
		value >>= 8;
		ret += 8;
	}
	if (value & 0xf0)
	{
		value >>= 4;
		ret += 4;
	}
	if (value & 0xc)
	{
		value >>= 2;
		ret += 2;
	}
	if (value & 0x2)
	{
		value >>= 1;
		ret += 1;
	}
	return ret;
}

#endif
