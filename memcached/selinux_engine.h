/*
 * selinux_engine.h
 *
 * Header file of the selinux engine module
 *
 *
 */
#ifndef SELINUX_ENGINE_H
#define SELINUX_ENGINE_H

#define TAG_MBTREE_NODE			0x01
#define TAG_MBTREE_LEAF			0x02
#define TAG_SELINUX_LABEL		0x03
#define TAG_SELINUX_ITEM		0x04

/*
 * mbtree.c - mmap based B-plus tree index
 */
typedef struct
{
	uint32_t	key;
	uint64_t	mnode;
	int			index;
} mbtree_scan;

extern uint64_t mbtree_lookup(void *handle, void *mbroot,
							  uint32_t key, mbtree_scan *scan);
extern uint64_t mbtree_next(void *handle, mbtree_scan *scan);
extern void mbtree_dump(void *handle, void *mbroot);
extern bool mbtree_insert(void *handle, void *mbroot, uint32_t key, uint64_t item);
extern bool mbtree_delete(void *handle, void *mbroot, uint32_t key, uint64_t item);
extern void *mbtree_create(void *handle);

/*
 * mblock.c - memory block management
 */
#define offset_to_addr(handle,offset)			\
	((void *)((unsigned long)(handle) + (offset)))
#define addr_to_offset(handle,addr)				\
	((uint64_t)((unsigned long)(addr) - (unsigned long)(handle)))

extern void *mblock_alloc(void *handle, size_t size);
extern void  mblock_free(void *handle, void *ptr);
extern void  mblock_reset(void *handle);
extern void  mblock_dump(void *handle);
extern void *mblock_init(int fdesc, size_t segment_size, bool debug,
						 bool (*callback_mchunk)(void *data, size_t size));

#endif
