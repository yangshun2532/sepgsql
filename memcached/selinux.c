/*
 * selinux.c
 *
 * access control facilities
 */
#include <assert.h>
#include "selinux_engine.h"



uint32_t
mselinux_check_alloc(selinux_engine_t *se, const void *cookie,
					 const void *key, size_t keylen)
{
	if (!se->config.selinux)
		return 0;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return 0;
}

bool
mselinux_check_create(selinux_engine_t *se, const void *cookie,
					  mcache_t *mcache)
{
	if (!se->config.selinux)
		return true;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return true;
}

bool
mselinux_check_read(selinux_engine_t *se, const void *cookie,
					mcache_t *mcache)
{
	if (!se->config.selinux)
		return true;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return true;
}

bool
mselinux_check_write(selinux_engine_t *se, const void *cookie,
					 mcache_t *old_cache, mcache_t *new_cache)
{
	if (!se->config.selinux)
		return true;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return true;
}

bool
mselinux_check_append(selinux_engine_t *se, const void *cookie,
					  mcache_t *old_cache, mcache_t *new_cache)
{
	if (!se->config.selinux)
		return true;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return true;
}

bool
mselinux_check_delete(selinux_engine_t *se, const void *cookie,
					  mcache_t *mcache)
{
	if (!se->config.selinux)
		return true;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return true;
}

bool
mselinux_check_arithmetic(selinux_engine_t *se, const void *cookie,
						  mcache_t *mcache)
{
	if (!se->config.selinux)
		return true;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return true;
}

bool
mselinux_check_flush(selinux_engine_t *se, const void *cookie)
{
	if (!se->config.selinux)
		return true;

	fprintf(stderr, "%s: \n", __FUNCTION__);

	return true;
}

bool
mselinux_init(selinux_engine_t *se)
{
	static struct selinux_opt	seopts[1] = {
		{
			.type = AVC_OPT_SETENFORCE,
			.value = NULL,
		},
	};
	int		num_opts = 0;

	if (!se->config.selinux)
		return true;

	/*
	 * Is the platform support SELinux?
	 */
	if (is_selinux_enabled() == 1)
	{
		se->info.features[se->info.num_features++].feature
			= ENGINE_FEATURE_ACCESS_CONTROL;
	}
	else
	{
		se->config.selinux = false;
		return true;
	}

	/*
	 * Is it permissive mode?
	 */
	if (!se->config.enforcing)
		num_opts++;

	/*
	 * Set up userspace access vector
	 */
	if (avc_open(seopts, num_opts) < 0)
		return false;

	return true;
}
