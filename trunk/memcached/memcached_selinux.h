/*
 * selinux_engine.h
 *
 * Header file of the selinux engine module
 *
 *
 */
#ifndef SELINUX_ENGINE_H
#define SELINUX_ENGINE_H

#include <pthread.h>

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
		/*
		 * MCHUNK_TAG_FREE
		 */
		struct {
			mlist_t		list;
		} free;
		/*
		 * MCHUNK_TAG_ITEM
		 */
#define MITEM_WITH_CAS	(1<<0)
#define MITEM_LINKED	(1<<8)
		struct {
			volatile uint16_t	flags;
			uint16_t	keylen;
			uint32_t	datalen;
			uint32_t	secid;
			uint32_t	exptime;
			uint8_t		data[0];
		} item;
		/*
		 * MCHUNK_TAG_BTREE
		 */
#define MBTREE_NUM_KEYS		7
		struct {
			uint64_t	parent;
			uint8_t		is_leaf;
			uint16_t	nkeys;	
			uint32_t	keys[MBTREE_NUM_KEYS];
			uint64_t	items[MBTREE_NUM_KEYS + 1];
		} btree;
		/*
		 * MCHUNK_TAG_LABEL
		 */
		struct {
			uint32_t	secid;
			uint32_t	refcount;
			uint8_t		label[0];
		} label;
	};
} mchunk_t;

/*
 * mbhead_t
 *
 * header structure of the memory block
 */
#define MBLOCK_MAGIC_STRING		"@MBLOCK_20100702"
#define MBLOCK_MIN_BITS			7	/* 128byte */
#define MBLOCK_MAX_BITS			25	/* 32MB */
#define MBLOCK_MIN_SIZE			(1<<MBLOCK_MIN_BITS)
#define MBLOCK_MAX_SIZE			(1<<MBLOCK_MAX_BITS)

typedef struct {
	char		magic[16];
	uint64_t	block_size;
	uint64_t	super_size;
	mlist_t		free_list[MBLOCK_MAX_BITS + 1];
	uint32_t	num_free[MBLOCK_MAX_BITS + 1];
	uint32_t	num_active[MBLOCK_MAX_BITS + 1];
	uint8_t		super_block[0];
} mhead_t;

#define offset_to_addr(mhead,offset)				\
	((offset)==0 ? NULL : ((void *)((unsigned long)(mhead) + (offset))))
#define addr_to_offset(mhead,addr)					\
	(!(addr) ? 0 : ((uint64_t)((unsigned long)(addr) - (unsigned long)(mhead))))
#define offset_of(type, member)						\
	((unsigned long) &((type *)0)->member)
#define container_of(ptr, type, member)				\
	(type *)(((char *)ptr) - offset_of(type, member))

static inline uint16_t
mchunk_magic(mhead_t *mhead, mchunk_t *mchunk)
{
	uint64_t	magic = addr_to_offset(mhead,mchunk) >> MBLOCK_MIN_BITS;

	magic ^= (magic >> 16);
	magic ^= (mchunk->mclass << 4);
	magic ^= (mchunk->tag) | (mchunk->tag << 8);

	return (magic ^ 0xa55a) & 0xffff;
}

#define mchunk_is_free(mc)	((mc)->tag == MCHUNK_TAG_FREE)
#define mchunk_is_item(mc)	((mc)->tag == MCHUNK_TAG_ITEM)
#define mchunk_is_btree(mc)	((mc)->tag == MCHUNK_TAG_BTREE)
#define mchunk_is_label(mc)	((mc)->tag == MCHUNK_TAG_LABEL)

/*
 * mitems.c - memory block based item management
 */
typedef struct mitem_s
{
	volatile uint16_t	refcnt;
} mitem_t;

/*
 * memcached_selinux.c
 */
typedef struct {
	ENGINE_HANDLE_V1		engine;
	SERVER_HANDLE_V1	   *server;

	pthread_rwlock_t		lock;
	mhead_t				   *mhead;
	mitem_t				   *mitems;
	rel_time_t				startup_time;

	/* configuration parameters */
	struct {
		char			   *filename;
		size_t				block_size;
		bool				selinux;
		bool				enforcing;
		bool				use_cas;
	} config;

	engine_info			info;
} selinux_engine;

extern void    *mitem_get_key(selinux_engine *se, mitem_t *mitem);
extern size_t   mitem_get_keylen(selinux_engine *se, mitem_t *mitem);
extern void    *mitem_get_data(selinux_engine *se, mitem_t *mitem);
extern size_t   mitem_get_datalen(selinux_engine *se, mitem_t *mitem);
extern uint16_t mitem_get_flags(selinux_engine *se, mitem_t *mitem);
extern uint64_t mitem_get_cas(selinux_engine *se, mitem_t *mitem);
extern uint32_t	mitem_get_exptime(selinux_engine *se, mitem_t *mitem);
extern void		mitem_set_flags(selinux_engine *se, mitem_t *mitem, uint16_t flags);
extern void		mitem_set_cas(selinux_engine *se, mitem_t *mitem, uint64_t cas);
extern void		mitem_set_exptime(selinux_engine *se, mitem_t *mitem, uint32_t exptime);
extern int		mitem_get_mclass(selinux_engine *se, mitem_t *mitem);

extern mitem_t *mitem_alloc(selinux_engine *se,
							const void *key, size_t key_len, size_t data_len);
extern bool     mitem_link(selinux_engine *se, mitem_t *mitem);
extern bool     mitem_unlink(selinux_engine *se, mitem_t *mitem);
extern mitem_t *mitem_get(selinux_engine *se, const void *key, size_t key_len);
extern void     mitem_put(selinux_engine *se, mitem_t *mitem);
extern void     mitem_get_info(selinux_engine *se, mitem_t *mitem,
							   item_info *item_info);

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

extern bool     mbtree_lookup(mhead_t *mhead, uint32_t key, mbtree_scan *scan);
extern bool     mbtree_insert(mhead_t *mhead, uint32_t key, uint64_t item);
extern bool     mbtree_delete(mhead_t *mhead, uint32_t key, uint64_t item);
extern void     mbtree_dump(mhead_t *mhead);
extern mhead_t *mbtree_open(int fdesc, size_t block_size);
extern void     mbtree_close(mhead_t *mhead);

/*
 * mblock.c - memory block management
 */
extern mchunk_t *mblock_alloc(mhead_t *mhead, uint8_t tag, size_t size);
extern void      mblock_free(mhead_t *mhead, mchunk_t *mchunk);
extern void      mblock_dump(mhead_t *mhead);
extern void      mblock_reset(mhead_t *mhead);
extern mhead_t  *mblock_map(int fdesc, size_t block_size, size_t super_size);
extern void      mblock_unmap(mhead_t *mhead);

#endif
