/*
 * mitems.c
 *
 * routines to manage item objects
 *
 *
 */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "memcached/engine.h"
#include "memcached_selinux.h"




mitem_t *
mitem_allocate(selinux_engine *se,
			   const void *key,
			   const size_t key_len,
			   const size_t data_len,
			   const int flags,
			   const rel_time_t exptime)
{}

bool
mitem_remove(mhead_t *mhead,
			 mitem_t *mitem)
{}

mitem_t *
mitem_get(mhead_t *mhead,
		  const void *key,
		  const size_t key_len,
	const size_t )
{}

void
mitem_put()
{}

void
miten_get_info(mhead_t *mhead,
			   mitem_t *mitem,
			   item_info *item_info)
{}
