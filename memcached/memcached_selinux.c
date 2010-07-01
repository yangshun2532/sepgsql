/*
 * memcached_selinux.c
 *
 * Source file of the selinux engine module
 *
 *
 *
 */

#include <pthread.h>

#include "memcached/engine.h"
#include "memcached_selinux.h"

typedef struct
{
	ENGINE_HANDLE_V1	engine;
	SERVER_HANDLE_V1	server;

	pthread_rwlock_t	lock;
	void			   *handle;
	struct {
		char		   *filename;
		size_t			block_size;
		char		   *hash_type;
		bool			use_cas;
		bool			selinux;
		bool			enforcing;
	} config;
	engine_info			info;
} selinux_engine;

const engine_info *
selinux_get_info(ENGINE_HANDLE* handle)
{
	selinux_engine *se = (selinux_engine *)handle;

	return &se->info;
}

static ENGINE_ERROR_CODE
selinux_initialize(ENGINE_HANDLE* handle,
				   const char *config_str)
{
	selinux_engine	   *se = (selinux_engine *)handle;
	ENGINE_ERROR_CODE	rc;
	struct config_item	options[] = {
		{ .key				= "filename",
		  .datatype			= DT_STRING,
		  .value.dt_string	= &se->config.filename,
		},
		{ .key				= "size",
		  .datatype			= DT_SIZE,
		  .value.dt_size	= &se->config.block_size,
		},
		{ .key				= "hash_type",
		  .datatype			= DT_STRING,
		  .value.dt_string	= &se->config.hash_type,
		},
		{ .key				= "use_cas",
		  .datatype			= DT_BOOL,
		  .value.dt_bool	= &se->config.use_cas,
		},
		{ .key				= "selinux",
		  .datatype			= DT_BOOL,
		  .value.dt_bool	= &se->config.selinux,
		},
		{ .key				= "enforcing",
		  .datatype			= DT_BOOL,
		  .value.dt_bool	= &se->config.enforcing,
		},
		{ .key = NULL }
	};

	if (config_str != NULL)
	{
		rc = se->server.core->parse_config(config_str, options, stderr);
		if (rc != ENGINE_SUCCESS)
			return rc;
	}

	/* Compare-And-Set operation available? */
	if (se->config.use_cas)
		se->info.features[se->info.num_features++] = ENGINE_FEATURE_CAS;
	/* Memory block is mapped to filesystem?  */
	if (se->config.filename)
	{
		struct stat		st_buf;

		if (stat(se->config.filename, &st_buf) != 0)
			return ENGINE_EINVAL;
		se->config.block_size = st_buf.st_size

		se->info.features[se->info.num_features++] = ENGINE_FEATURE_PERSISTENT_STORAGE;
	}
	/* SELinux is enabled? */
	if (se->config.selinux)
	{
		if (is_selinux_enabled() == 1)
			se->info.features[se->info.num_features++] = ENGINE_FEATURE_ACCESS_CONTROL;
		else
			se->config.selinux = false;	/* SELinux is disabled */
	}

	/*
	 * Load Hash/B+Tree Index
	 */
	if (strcmp(se->config.index, "btree") == 0)
		se->handle = mbtree_init(fdesc, se->config.block_size);
	else if (strcmp(se->config.index, "hash") == 0)
		se->handle = mhash_init(fdesc, se->config.block_size);
	else
		return ENGINE_ENOTSUP;

	if (!se->handle)
		return ENGINE_EINVAL;

	return ENGINE_SUCCESS;
}

static void
selinux_destroy(ENGINE_HANDLE *handle)
{

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
{}

static ENGINE_ERROR_CODE
selinux_remove(ENGINE_HANDLE *handle,
			   const void *cookie,
			   const void *key,
			   const size_t nkey,
			   uint64_t cas,
			   uint16_t vbucket)
{
	if (vbucket != 0)
		return ENGINE_ENOTSUP;
}

static void
selinux_release(ENGINE_HANDLE* handle, const
				void *cookie,
				item* item)
{}

static ENGINE_ERROR_CODE
selinux_get(ENGINE_HANDLE *handle,
			const void *cookie,
			item **item,
			const void *key,
			const int nkey,
			uint16_t vbucket)
{
	selinux_engine *se = (selinux_engine *)handle;

	if (vbucket != 0)
		return ENGINE_ENOTSUP;




}

static ENGINE_ERROR_CODE
selinux_store(ENGINE_HANDLE* handle,
			  const void *cookie,
			  item *item,
			  uint64_t *cas,
			  ENGINE_STORE_OPERATION operation,
			  uint16_t vbucket)
{
	if (vbucket != 0)
		return ENGINE_ENOTSUP;


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
	if (vbucket != 0)
		return ENGINE_ENOTSUP;

}

static ENGINE_ERROR_CODE
selinux_flush(ENGINE_HANDLE *handle,
			  const void *cookie,
			  time_t when)
{}

static ENGINE_ERROR_CODE
selinux_get_stats(ENGINE_HANDLE *handle,
				  const void *cookie,
				  const char *stat_key,
				  int nkey,
				  ADD_STAT add_stat)
{}

static void
selinux_reset_stats(ENGINE_HANDLE* handle,
					const void *cookie)
{}

static void *
selinux_get_stats_struct(ENGINE_HANDLE* handle,
						 const void *cookie)
{}

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
{}

static bool
selinux_get_item_info(ENGINE_HANDLE *handle,
					  const item *item,
					  item_info *item_info)
{}

static selinux_engine selinux_engine_catalog = {
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
	.lock	= PTHREAD_RWLOCK_INITIALIZER,
	.config = {
		.filename			= NULL,
		.block_size			= 64 * 1024 * 1024,
		.index				= "btree",
		.use_cas			= true,
		.selinux			= true,
		.enforcing			= true,
	},
	.info = {
		.description = "Memcached/SELinux v0.1",
		.num_features = 0;
	},
};

ENGINE_ERROR_CODE
create_instance(uint64_t interface,
				GET_SERVER_API get_server_api,
				ENGINE_HANDLE** handle)
{
	selinux_engine	   *se;
	SERVER_HANDLE_V1   *server = get_server_api();

	if (interface != 1 || !server)
		return ENGINE_ENOTSUP;

	se = malloc(sizeof(selinux_engine) +
				sizeof(feature_info) * LAST_REGISTERED_ENGINE_FEATURE);
	if (!se)
		return ENGINE_ENOMEM;

	memcpy(se, &selinux_engine_catalog, sizeof(selinux_engine));
	memcpy(&se->server, server, sizeof(SERVER_HANDLE_V1));

	*handle = &se->engine;

	return ENGINE_SUCCESS;
}
