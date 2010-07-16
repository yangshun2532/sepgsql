/*
 * memcached_selinux.c
 *
 * Source file of the selinux engine module
 *
 *
 *
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "selinux_engine.h"

#if 1
/* copy from util.c */
#include <ctype.h>
bool safe_strtoull(const char *str, uint64_t *out) {
    assert(out != NULL);
    errno = 0;
    *out = 0;
    char *endptr;
    unsigned long long ull = strtoull(str, &endptr, 10);
    if (errno == ERANGE)
        return false;
    if (isspace(*endptr) || (*endptr == '\0' && endptr != str)) {
        if ((long long) ull < 0) {
            /* only check for negative signs in the uncommon case when
             * the unsigned number is so big that it's negative as a
             * signed number. */
            if (strchr(str, '-') != NULL) {
                return false;
            }
        }
        *out = ull;
        return true;
    }
    return false;
}
#endif

const engine_info *
selinux_get_info(ENGINE_HANDLE* handle)
{
	selinux_engine_t *se = (selinux_engine_t *)handle;

	return &se->info;
}

static ENGINE_ERROR_CODE
selinux_initialize(ENGINE_HANDLE* handle,
				   const char *config_str)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	ENGINE_ERROR_CODE	rc;
	size_t				mblock_size;
	struct config_item	options[] = {
		{ .key				= "filename",
		  .datatype			= DT_STRING,
		  .value.dt_string	= &se->config.filename,
		},
		{ .key				= "size",
		  .datatype			= DT_SIZE,
		  .value.dt_size	= &se->config.block_size,
		},
		{ .key				= "use_cas",
		  .datatype			= DT_BOOL,
		  .value.dt_bool	= &se->config.use_cas,
		},
		{ .key				= "selinux",
		  .datatype			= DT_BOOL,
		  .value.dt_bool	= &se->config.selinux,
		},
		{ .key				= "reclaim",
		  .datatype			= DT_BOOL,
		  .value.dt_bool	= &se->config.reclaim,
		},
		{ .key				= "debug",
		  .datatype			= DT_BOOL,
		  .value.dt_bool	= &se->config.debug,
		},
		{ .key = NULL }
	};

	/*
	 * Parse configurations
	 */
	if (config_str != NULL)
	{
		rc = se->server.core->parse_config(config_str, options, stderr);
		if (rc != ENGINE_SUCCESS)
			return rc;
	}

	/* Adjust startup_time */
	se->startup_time = time(NULL) - se->server.core->get_current_time();

	/* CAS operation available? */
	if (se->config.use_cas)
		se->info.features[se->info.num_features++].feature
			= ENGINE_FEATURE_CAS;
	/* Persistent storage available? */
	if (se->config.filename)
	{
		if (access(se->config.filename, R_OK | W_OK) != 0)
			return false;
		se->info.features[se->info.num_features++].feature
			= ENGINE_FEATURE_PERSISTENT_STORAGE;
	}
	/* Initialize SELinux support */
	if (!mselinux_init(se))
	  return ENGINE_ENOMEM;

	/*
	 * Load B+tree index
	 */
	mblock_size = se->config.block_size * MBLOCK_MIN_SIZE / (MBLOCK_MIN_SIZE + 2);
	mblock_size &= ~(sysconf(_SC_PAGESIZE) - 1);

	if (se->config.filename)
	{
		se->config.fdesc = open(se->config.filename, O_RDWR);
		if (se->config.fdesc < 0)
			return ENGINE_EINVAL;
	}
	se->mhead = mbtree_open(se->config.fdesc, mblock_size);
	if (!se->mhead)
		return ENGINE_ENOMEM;

	if (!mcache_init(se))
	{
		mbtree_close(se->mhead);
		return ENGINE_ENOMEM;
	}

	/*
	 * Dump configuration
	 */
	fprintf(stderr,
			"selinux_engine.config.filename = %s\n"
			"selinux_engine.config.size = %" PRIu64 "\n"
			"selinux_engine.config.use_cas = %s\n"
			"selinux_engine.config.selinux = %s\n"
			"selinux_engine.config.reclaim = %s\n"
			"selinux_engine.config.debug = %s\n",
			se->config.filename ? se->config.filename : "(null)",
			se->config.block_size,
			se->config.use_cas ? "true" : "false",
			se->config.selinux ? "true" : "false",
			se->config.reclaim ? "true" : "false",
			se->config.debug ? "true" : "false");

	return ENGINE_SUCCESS;
}

static void
selinux_destroy(ENGINE_HANDLE *handle)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	mcache_t		   *mcache, *next;
	int					index;

	mselinux_fini(se);

	for (index = 0; index < se->mcache.size; index++)
	{
		for (mcache = se->mcache.slots[index]; mcache; mcache = next)
		{
			next = mcache->next;

			free(mcache);
		}
	}
	for (mcache = se->mcache.free_list; mcache; mcache = next)
	{
		next = mcache->next;

		free(mcache);
	}
	if (se->mhead != NULL)
		mbtree_close(se->mhead);

	close(se->config.fdesc);
}

static ENGINE_ERROR_CODE
selinux_allocate(ENGINE_HANDLE *handle,
				 const void *cookie,
				 item **item,
				 const void *key,
				 const size_t nkey,
				 const size_t nbytes,
				 const int flags,
				 const rel_time_t exptime)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	mcache_t		   *mcache;
	uint32_t			secid = 0;

	if (nbytes >= MBLOCK_MAX_SIZE - sizeof(mchunk_t))
		return ENGINE_E2BIG;

	pthread_rwlock_wrlock(&se->lock);

	secid = mselinux_check_alloc(se, cookie, key, nkey);

	fprintf(stderr, "%s: secid=%u\n", __FUNCTION__, secid);

	mcache = mcache_alloc(se, key, nkey, nbytes, secid, flags, exptime);

	pthread_rwlock_unlock(&se->lock);

	if (!mcache)
		return ENGINE_ENOMEM;

	*item = mcache;

	return ENGINE_SUCCESS;
}

static ENGINE_ERROR_CODE
selinux_remove(ENGINE_HANDLE *handle,
			   const void *cookie,
			   const void *key,
			   const size_t nkey,
			   uint64_t cas,
			   uint16_t vbucket)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	mcache_t		   *mcache;
	ENGINE_ERROR_CODE	rc = ENGINE_SUCCESS;

	if (vbucket != 0)
		return ENGINE_ENOTSUP;

	pthread_rwlock_wrlock(&se->lock);

	mcache = mcache_get(se, key, nkey);
	if (!mcache)
	{
		pthread_rwlock_unlock(&se->lock);

		return ENGINE_KEY_ENOENT;
	}
	if (cas != 0 && cas != mcache_get_cas(mcache))
		rc = ENGINE_KEY_EEXISTS;
	else if (!mselinux_check_delete(se, cookie, mcache))
		rc = ENGINE_EACCESS;
	else
		mcache_unlink(se, mcache);

	mcache_put(se, mcache);

	pthread_rwlock_unlock(&se->lock);

	return rc;
}

static void
selinux_release(ENGINE_HANDLE* handle, const
				void *cookie,
				item* item)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	mcache_t		   *mcache = (mcache_t *)item;
	uint16_t			flags;

	pthread_rwlock_rdlock(&se->lock);
	/*
	 * If MITEM_LINKED is not set, mitem_put() may also unlink
	 * a security label associated, so it needs to be writer
	 * locked.
	 */
	flags = mcache_get_flags(mcache);
	if ((flags & MITEM_LINKED) == 0)
	{
		pthread_rwlock_unlock(&se->lock);
		pthread_rwlock_wrlock(&se->lock);
	}
	mcache_put(se, mcache);

	pthread_rwlock_unlock(&se->lock);
}

static ENGINE_ERROR_CODE
selinux_get(ENGINE_HANDLE *handle,
			const void *cookie,
			item **item,
			const void *key,
			const int nkey,
			uint16_t vbucket)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	mcache_t		   *mcache;
	bool				lock_is_exclusive = false;

	if (vbucket != 0)
		return ENGINE_ENOTSUP;

	pthread_rwlock_rdlock(&se->lock);
retry:
	mcache = mcache_get(se, key, nkey);

	/*
	 * If the required item is already expired, we unlink it and report
	 * users that no item were not found with this key.
	 */
	if (mcache != NULL && mcache_is_expired(se, mcache))
	{
		/*
		 * We cannot unlink the item with read-lock, so we retry same
		 * steps with write-lock again. Then, it will be unlinked, or
		 * other thread may already unlink it.
		 */
		if (!lock_is_exclusive)
		{
			mcache_put(se, mcache);
			pthread_rwlock_unlock(&se->lock);
			lock_is_exclusive = true;
			pthread_rwlock_wrlock(&se->lock);
			goto retry;
		}
		mcache_unlink(se, mcache);
		mcache_put(se, mcache);
		mcache = NULL;
	}
	if (mcache && !mselinux_check_read(se, cookie, mcache))
	{
		mcache_put(se, mcache);
		pthread_rwlock_unlock(&se->lock);
		return ENGINE_EACCESS;
	}

	if (!mcache)
		__sync_add_and_fetch(&se->stats.num_misses, 1);
	else
		__sync_add_and_fetch(&se->stats.num_hits, 1);

	pthread_rwlock_unlock(&se->lock);

	if (!mcache)
		return ENGINE_KEY_ENOENT;

	*item = mcache;

	return ENGINE_SUCCESS;
}

static ENGINE_ERROR_CODE
selinux_store(ENGINE_HANDLE* handle,
			  const void *cookie,
			  item *item,
			  uint64_t *cas,
			  ENGINE_STORE_OPERATION operation,
			  uint16_t vbucket)
{
	ENGINE_ERROR_CODE	rc = ENGINE_NOT_STORED;
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	mcache_t		   *new_cache = item;
	mcache_t		   *old_cache;
	void			   *key;
	size_t				key_len;

	if (vbucket != 0)
		return ENGINE_ENOTSUP;

	pthread_rwlock_wrlock(&se->lock);

	key = mcache_get_key(new_cache);
	key_len = mcache_get_keylen(new_cache);
	old_cache = mcache_get(se, key, key_len);

	if (old_cache != NULL && mcache_is_expired(se, old_cache))
	{
		mcache_unlink(se, old_cache);
		mcache_put(se, old_cache);
		old_cache = NULL;
	}

	switch (operation)
	{
		case OPERATION_ADD:
			/*
			 * ADD only adds a nonexistent item.
			 */
			if (old_cache == NULL)
			{
				if (!mselinux_check_create(se, cookie, new_cache))
				{
					rc = ENGINE_EACCESS;
					break;
				}
				mcache_link(se, new_cache);
				rc = ENGINE_SUCCESS;
			}
			break;

		case OPERATION_SET:
			if (old_cache == NULL)
			{
				if (!mselinux_check_create(se, cookie, new_cache))
				{
					rc = ENGINE_EACCESS;
					break;
				}
			}
			else
			{
				if (!mselinux_check_write(se, cookie, old_cache, new_cache))
				{
					rc = ENGINE_EACCESS;
					break;
				}
				mcache_unlink(se, old_cache);
			}
			mcache_link(se, new_cache);
			rc = ENGINE_SUCCESS;
			break;

		case OPERATION_REPLACE:
			/*
			 * REPLACE only replaces an existing value
			 */
			if (old_cache != NULL)
			{
				if (!mselinux_check_write(se, cookie, old_cache, new_cache))
				{
					rc = ENGINE_EACCESS;
					break;
				}
				mcache_link(se, new_cache);
				mcache_unlink(se, old_cache);

				rc = ENGINE_SUCCESS;
			}
			break;

		case OPERATION_APPEND:
		case OPERATION_PREPEND:
			if (old_cache != NULL)
			{
				mcache_t   *mcache;
				void	   *data;
				size_t		data_len;
				void	   *old_data	= mcache_get_data(old_cache);
				size_t		old_length	= mcache_get_datalen(old_cache);
				void	   *new_data	= mcache_get_data(new_cache);
				size_t		new_length	= mcache_get_datalen(new_cache);

				if (!mselinux_check_append(se, cookie, old_cache, new_cache))
				{
					rc = ENGINE_EACCESS;
					break;
				}

				data_len = old_length + new_length - 2;
				mcache = mcache_alloc(se, key, key_len, data_len,
									  mcache_get_secid(old_cache),
									  mcache_get_flags(old_cache),
									  mcache_get_exptime(se, old_cache));
				if (!mcache)
					break;

				data = mcache_get_data(mcache);

				if (operation == OPERATION_APPEND)
				{
					memcpy(data, old_data, old_length);
					memcpy(data + old_length - 2, new_data, new_length);
				}
				else
				{
					memcpy(data, new_data, new_length);
					memcpy(data + new_length - 2, old_data, old_length);
				}
				mcache_link(se, mcache);
				mcache_unlink(se, old_cache);

				mcache_put(se, mcache);

				rc = ENGINE_SUCCESS;
			}
			break;

		case OPERATION_CAS:
			if (old_cache != NULL)
			{
				if (mcache_get_cas(old_cache) != mcache_get_cas(new_cache))
					rc = ENGINE_KEY_EEXISTS;
				else if (!mselinux_check_write(se, cookie, old_cache, new_cache))
					rc = ENGINE_EACCESS;
				else
				{
					mcache_link(se, new_cache);
					mcache_unlink(se, old_cache);
				}
			}
			break;

		default:
			/* should be never happen */
			break;
	}
	if (old_cache)
		mcache_put(se, old_cache);

	pthread_rwlock_unlock(&se->lock);

	return rc;
}

static ENGINE_ERROR_CODE
selinux_arithmetic(ENGINE_HANDLE* handle,
				   const void *cookie,
				   const void *key,
				   const int nkey,
				   const bool increment,
				   const bool create,
				   const uint64_t delta,
				   const uint64_t initial,
				   const rel_time_t exptime,
				   uint64_t *cas,
				   uint64_t *result,
				   uint16_t vbucket)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	mcache_t		   *old_cache;
	mcache_t		   *new_cache;
	uint64_t			value;
	uint32_t			secid = 0;
	char			   *data;
	char				buffer[256];
	size_t				length;
	ENGINE_ERROR_CODE	rc = ENGINE_SUCCESS;

	if (vbucket != 0)
		return ENGINE_ENOTSUP;

    pthread_rwlock_wrlock(&se->lock);

	old_cache = mcache_get(se, key, nkey);
	if (!old_cache)
	{
		if (!create)
		{
			rc = ENGINE_KEY_ENOENT;
			goto out_unlock;
		}
		length = snprintf(buffer, sizeof(buffer), "%"PRIu64"\r\n",
						  (uint64_t) initial);
		new_cache = mcache_alloc(se, key, nkey, length, secid, 0, exptime);
		if (!new_cache)
		{
			rc = ENGINE_ENOMEM;
			goto out_unlock;
		}
		data = mcache_get_data(new_cache);
		memcpy(data, buffer, length);

		if (!mselinux_check_create(se, cookie, new_cache))
			rc = ENGINE_EACCESS;
		else
			mcache_link(se, new_cache);

		mcache_put(se, new_cache);

		*result = initial;
		*cas = mcache_get_cas(new_cache);
	}
	else
	{
		if (!safe_strtoull(mcache_get_data(old_cache), &value))
		{
			rc = ENGINE_EINVAL;
			goto out_unlock;
		}

		if (increment)
			value += delta;
		else if (delta > value)
			value = 0;
		else
			value -= delta;

		length = snprintf(buffer, sizeof(buffer), "%"PRIu64"\r\n",
						  (uint64_t) value);
		new_cache = mcache_alloc(se, key, nkey, length,
								 mcache_get_secid(old_cache),
								 mcache_get_flags(old_cache),
								 mcache_get_exptime(se, old_cache));
		if (!new_cache)
		{
			rc = ENGINE_ENOMEM;
			goto out_unlock;
		}
		data = mcache_get_data(new_cache);
		memcpy(data, buffer, length);

		mcache_set_cas(new_cache, mcache_get_cas(old_cache));

		if (!mselinux_check_arithmetic(se, cookie, old_cache))
			rc = ENGINE_EACCESS;
		else
		{
			mcache_link(se, new_cache);
			mcache_unlink(se, old_cache);
		}
		mcache_put(se, new_cache);

		*result = value;
		*cas = mcache_get_cas(new_cache);
	}
out_unlock:
	if (old_cache)
		mcache_put(se, old_cache);
	pthread_rwlock_unlock(&se->lock);

	return rc;
}

static ENGINE_ERROR_CODE
selinux_flush(ENGINE_HANDLE *handle,
			  const void *cookie,
			  time_t when)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;

	pthread_rwlock_wrlock(&se->lock);

	if (!mselinux_check_flush(se, cookie))
		mcache_flush(se, when);

	pthread_rwlock_unlock(&se->lock);

	return ENGINE_SUCCESS;
}

static ENGINE_ERROR_CODE
selinux_get_stats(ENGINE_HANDLE *handle,
				  const void *cookie,
				  const char *stat_key,
				  int nkey,
				  ADD_STAT add_stat)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;
	ENGINE_ERROR_CODE	ret = ENGINE_SUCCESS;
	char				kbuf[128];
	char				vbuf[128];
	size_t				klen, vlen;

	if (stat_key == NULL)
	{
		vlen = sprintf(vbuf, "%" PRIu64, se->stats.reclaimed);
		add_stat("reclaimed",   9, vbuf, vlen, cookie);

		vlen = sprintf(vbuf, "%" PRIu64, se->stats.num_hits);
		add_stat("num_hits",    8, vbuf, vlen, cookie);

		vlen = sprintf(vbuf, "%" PRIu64, se->stats.num_misses);
		add_stat("num_misses", 10, vbuf, vlen, cookie);
	}
	else if (strncmp(stat_key, "chunks", 5) == 0)
	{
		int				mclass;

		for (mclass = MBLOCK_MIN_BITS; mclass <= MBLOCK_MAX_BITS; mclass++)
		{
			klen = sprintf(kbuf, "%u:chunk.size", mclass);
			vlen = sprintf(vbuf, "%" PRIu32, (1<<mclass));
			add_stat(kbuf, klen, vbuf, vlen, cookie);

			klen = sprintf(kbuf, "%u:chunk.num_free", mclass);
			vlen = sprintf(vbuf, "%" PRIu32, se->mhead->num_free[mclass]);
			add_stat(kbuf, klen, vbuf, vlen, cookie);

			klen = sprintf(kbuf, "%u:chunk.num_actives", mclass);
			vlen = sprintf(vbuf, "%" PRIu32, se->mhead->num_active[mclass]);
			add_stat(kbuf, klen, vbuf, vlen, cookie);
		}
	}
	else
	{
		ret = ENGINE_KEY_ENOENT;
	}
	return ENGINE_SUCCESS;
}

static void
selinux_reset_stats(ENGINE_HANDLE* handle,
					const void *cookie)
{
	selinux_engine_t   *se = (selinux_engine_t *)handle;

	pthread_rwlock_wrlock(&se->lock);

	se->stats.reclaimed = 0;
	se->stats.num_hits = 0;
	se->stats.num_misses = 0;

	pthread_rwlock_unlock(&se->lock);
}

static ENGINE_ERROR_CODE
selinux_unknown_command(ENGINE_HANDLE *handle,
						const void *cookie,
						protocol_binary_request_header *request,
						ADD_RESPONSE response)
{
	return ENGINE_ENOTSUP;
}

static void
selinux_item_set_cas(ENGINE_HANDLE *handle,
					 item *item,
					 uint64_t cas)
{
	mcache_t		   *mcache = item;

	mcache_set_cas(mcache, cas);
}

static bool
selinux_get_item_info(ENGINE_HANDLE *handle,
					  const item *item,
					  item_info *item_info)
{
	selinux_engine_t   *se		= (selinux_engine_t *)handle;
	mcache_t		   *mcache	= (mcache_t *)item;

	if (item_info->nvalue < 1)
		return false;

	item_info->cas		= mcache_get_cas(mcache);
	item_info->exptime	= mcache_get_exptime(se, mcache);
	item_info->nbytes	= mcache_get_datalen(mcache);
	item_info->flags	= mcache_get_flags(mcache);
	item_info->clsid	= mcache_get_mclass(mcache);
	item_info->nkey		= mcache_get_keylen(mcache);
	item_info->nvalue	= 1;
	item_info->key		= mcache_get_key(mcache);
	item_info->value[0].iov_base	= mcache_get_data(mcache);
	item_info->value[0].iov_len		= mcache_get_datalen(mcache);

	return true;
}

static selinux_engine_t selinux_engine_catalog = {
	.engine = {
		.interface = {
			.interface = 1
		},
		.get_info			= selinux_get_info,
		.initialize			= selinux_initialize,
		.destroy			= selinux_destroy,
		.allocate			= selinux_allocate,
		.remove				= selinux_remove,
		.release			= selinux_release,
		.get				= selinux_get,
		.get_stats			= selinux_get_stats,
		.reset_stats		= selinux_reset_stats,
		.store				= selinux_store,
		.arithmetic			= selinux_arithmetic,
		.flush				= selinux_flush,
		.unknown_command	= selinux_unknown_command,
		.item_set_cas		= selinux_item_set_cas,
		.get_item_info		= selinux_get_item_info,
	},
	.lock					= PTHREAD_RWLOCK_INITIALIZER,
	.thread					= 0,
	.mhead					= NULL,
	.scan = {
		.key				= 0,
		.item				= 0,
	},
	.mcache = {
		.slots				= NULL,
		.locks				= NULL,
		.lru_hint			= 0,
		.free_list			= NULL,
		.free_lock			= PTHREAD_MUTEX_INITIALIZER,
		.num_actives		= 0,
		.num_frees			= 0,
	},
	.config = {
		.filename			= NULL,
		.fdesc				= -1,
		.block_size			= 64 * 1024 * 1024,
		.use_cas			= true,
		.selinux			= true,
		.reclaim			= false,
		.debug				= true,
	},
	.info = {
		.description = "memcached/selinux v0.1",
		.num_features = 0,
	},
};

ENGINE_ERROR_CODE
create_instance(uint64_t interface,
				GET_SERVER_API get_server_api,
				ENGINE_HANDLE** handle)
{
	selinux_engine_t   *se;
	SERVER_HANDLE_V1   *server = get_server_api();

	if (interface != 1 || !server)
		return ENGINE_ENOTSUP;

	se = malloc(sizeof(selinux_engine_t) +
				sizeof(feature_info) * LAST_REGISTERED_ENGINE_FEATURE);
	if (!se)
		return ENGINE_ENOMEM;

	memcpy(se, &selinux_engine_catalog, sizeof(selinux_engine_t));
	memcpy(&se->server, server, sizeof(SERVER_HANDLE_V1));

	*handle = (ENGINE_HANDLE *)&se->engine;

	return ENGINE_SUCCESS;
}
