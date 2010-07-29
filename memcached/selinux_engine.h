/*
 * selinux_engine.h
 *
 *	Header file of the selinux_engine module
 *
 * Copyright (C) 2010, NEC Corporation
 *
 * Authors: KaiGai Kohei <kaigai@ak.jp.nec.com> 
 *
 * This program is distributed under the modified BSD license.
 * See the LICENSE file for full text.
 */
#ifndef SELINUX_ENGINE_H
#define SELINUX_ENGINE_H

#include <pthread.h>
#include <selinux/selinux.h>
#include <selinux/avc.h>
#include "memcached/engine.h"
#include "memcached/util.h"

typedef struct selinux_engine_s selinux_engine_t;

/*
 * mlist_t
 *
 * A type for dual linked list on the memory block
 */
typedef struct {
	uint64_t	prev;
	uint64_t	next;
} mlist_t;

/*
 * mchunk_t
 *
 * A type for memory block chunk for various kind of chunk classes.
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
			char		value[1];
		} label;
	};
} mchunk_t;

/*
 * mbhead_t
 *
 * A type for header structure of the memory block
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
	uint32_t	last_secid;
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
 * mcache.c - local item/label management
 */
typedef struct mcache_s mcache_t;
struct mcache_s
{
	mcache_t	   *next;
	volatile int	refcnt;
	bool			is_hot;
	security_id_t	tsid;
	mchunk_t	   *mchunk;
};

extern void		*mcache_get_key(mcache_t *mcache);
extern size_t	 mcache_get_keylen(mcache_t *mcache);
extern void		*mcache_get_data(mcache_t *mcache);
extern size_t	 mcache_get_datalen(mcache_t *mcache);
extern uint64_t	 mcache_get_cas(mcache_t *mcache);
extern void		 mcache_set_cas(mcache_t *mcache, uint64_t cas);
extern uint16_t	 mcache_get_flags(mcache_t *mcache);
extern uint32_t	 mcache_get_secid(mcache_t *mcache);
extern int		 mcache_get_mclass(mcache_t *mcache);
extern bool		 mcache_is_expired(selinux_engine_t *se, mcache_t *mcache);
extern uint32_t	 mcache_get_exptime(selinux_engine_t *se, mcache_t *mcache);
extern mcache_t *mcache_alloc(selinux_engine_t *se,
							  const void *key, size_t key_len, size_t data_len,
							  uint32_t secid, int flags, rel_time_t exptime);
extern bool		 mcache_link(selinux_engine_t *se, mcache_t *mcache);
extern bool		 mcache_unlink(selinux_engine_t *se, mcache_t *mcache);
extern mcache_t *mcache_get(selinux_engine_t *se, const void *key, size_t key_len);
extern void		 mcache_put(selinux_engine_t *se, mcache_t *mcache);
extern void		 mcache_flush(selinux_engine_t *se, const void *cookie, time_t when);
extern bool		 mcache_init(selinux_engine_t *se);

extern mchunk_t *mlabel_lookup_secid(selinux_engine_t *se, uint32_t secid);
extern mchunk_t *mlabel_lookup_label(selinux_engine_t *se, const char *label);
extern uint32_t	 mlabel_get(selinux_engine_t *se, const char *label);
extern bool		 mlabel_put(selinux_engine_t *se, uint32_t secid);

/*
 * mbtree.c - mmap based B-plus tree index
 */
typedef struct
{
	uint64_t	mnode;
	int			index;
	uint32_t	key;
	uint64_t	item;
} mbtree_scan;

extern bool     mbtree_lookup(mhead_t *mhead, mbtree_scan *scan);
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

/*
 * selinux.c - routines to support access control
 */
extern uint32_t	mselinux_check_alloc(selinux_engine_t *se, const void *cookie,
									 const void *key, size_t keylen);
extern bool		mselinux_check_create(selinux_engine_t *se, const void *cookie,
									  mcache_t *mcache);
extern bool		mselinux_check_read(selinux_engine_t *se, const void *cookie,
									mcache_t *mcache);
extern bool		mselinux_check_write(selinux_engine_t *se, const void *cookie,
									 mcache_t *old_cache, mcache_t *new_cache);
extern bool		mselinux_check_append(selinux_engine_t *se, const void *cookie,
									  mcache_t *old_cache, mcache_t *new_cache);
extern bool		mselinux_check_remove(selinux_engine_t *se, const void *cookie,
									  mcache_t *mcache);
extern bool		mselinux_check_calculate(selinux_engine_t *se, const void *cookie,
										 mcache_t *mcache);
extern bool		mselinux_check_relabel(selinux_engine_t *se, const void *cookie,
									   mcache_t *old_cache, mcache_t *new_cache);
extern bool		mselinux_init(selinux_engine_t *se);
extern void		mselinux_fini(selinux_engine_t *se);

/*
 * interfaces.c
 */
struct selinux_engine_s {
	ENGINE_HANDLE_V1		engine;
	SERVER_HANDLE_V1		server;

	pthread_rwlock_t		lock;
	pthread_t				thread;
	mhead_t				   *mhead;
	mbtree_scan				scan;

	rel_time_t				startup_time;

	/* SELinux protocol extension */
	EXTENSION_ASCII_PROTOCOL_DESCRIPTOR		ascii_proto;

	/* mcache status */
	struct {
		mcache_t		  **slots;
		pthread_mutex_t	   *locks;
		int					size;
		volatile int		lru_hint;
		mcache_t		   *free_list;
		pthread_mutex_t		free_lock;
		uint32_t			num_actives;
		uint32_t			num_frees;
	} mcache;

	/* configuration parameters */
	struct {
		char			   *filename;
		int					fdesc;
		size_t				block_size;
		bool				selinux;
		bool				use_cas;
		bool				reclaim;
		bool				debug;
	} config;

	/* runtime statics parameters */
	struct {
		uint64_t			reclaimed;
		uint64_t			num_hits;
		uint64_t			num_misses;
	} stats;

	engine_info				info;
};

#endif
