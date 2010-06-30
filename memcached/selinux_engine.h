/*
 * selinux_engine.h
 *
 * Header file of the selinux engine module
 *
 *
 */
#ifndef SELINUX_ENGINE_H
#define SELINUX_ENGINE_H

#define TAG_SELINUX_LABEL		0x03
#define TAG_SELINUX_ITEM		0x04

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

extern bool mbtree_lookup(void *handle, uint32_t key, mbtree_scan *scan);
extern void mbtree_dump(void *handle);
extern bool mbtree_insert(void *handle, uint32_t key, uint64_t item);
extern bool mbtree_delete(void *handle, uint32_t key, uint64_t item);
extern void *mbtree_init(int fdesc, size_t block_size);

/*
 * mblock.c - memory block management
 */
extern uint64_t mblock_addr_to_offset(void *handle, void *addr);
extern void *mblock_offset_to_addr(void *handle, uint64_t offset);
extern void *mblock_alloc(void *handle, size_t size);
extern void  mblock_free(void *handle, void *ptr);
extern void  mblock_reset(void *handle);
extern void  mblock_dump(void *handle);
extern void *mblock_init(int fdesc, size_t block_size, size_t super_size);
extern void  mblock_unmap(void *handle);

#endif
