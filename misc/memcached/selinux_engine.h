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
#define TAG_KV_ITEM				0x02





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
extern void  mblock_stat(void *handle, char *buffer, size_t buflen);
extern void *mblock_init(int fdesc, size_t segment_size,
						 bool (*callback_mchunk)(void *data, size_t size));

#endif
