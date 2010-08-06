/*
 * selinux.c - Routines to make access control decision using SELinux
 *
 * Copyright (C) 2010, NEC Corporation
 *
 * Authors: KaiGai Kohei <kaigai@ak.jp.nec.com> 
 *
 * This program is distributed under the modified BSD license.
 * See the LICENSE file for full text.
 */
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include "selinux_engine.h"

static struct {
	pthread_rwlock_t	lock;
	security_class_t	tclass;
	access_vector_t		create;
	access_vector_t		getattr;
	access_vector_t		setattr;
	access_vector_t		remove;
	access_vector_t		relabelfrom;
	access_vector_t		relabelto;
	access_vector_t		read;
	access_vector_t		write;
	access_vector_t		append;
	access_vector_t		calculate;
} permissions = {
	.lock				= PTHREAD_RWLOCK_INITIALIZER,
};

uint32_t
mselinux_check_alloc(selinux_engine_t *se, const void *cookie,
					 const void *key, size_t keylen)
{
	static security_id_t	tsid = NULL;
	mcache_t	   *mcache;
	security_id_t	ssid;
	security_id_t	nsid;
	uint32_t		secid;

	if (!se->config.selinux)
		return 0;

	if (!tsid)
	{
		security_context_t	context;

		if (getcon_raw(&context) < 0)
			return 0;

		if (avc_context_to_sid_raw(context, &tsid) < 0)
		{
			freecon(context);
			return 0;
		}
		freecon(context);
	}

	/*
	 * It the new allocation tries to replace an existing key,
	 * we copy security id from the older chunk.
	 */
	mcache = mcache_get(se, key, keylen);
	if (mcache)
	{
		secid = mcache->mchunk->item.secid;
		if (secid > 0)
		{
			mchunk_t   *lchunk = mlabel_lookup_secid(se, secid);
			if (!lchunk)
				secid = 0;
			else
				lchunk->label.refcount++;
		}
		return secid;
	}

	ssid = se->server.core->get_engine_specific(cookie);

	pthread_rwlock_rdlock(&permissions.lock);

	avc_compute_create(ssid, tsid, permissions.tclass, &nsid);

	pthread_rwlock_unlock(&permissions.lock);

	secid = mlabel_get(se, nsid->ctx);

	if (se->config.debug)
		fprintf(stderr, "%s: ssid=%s tsid=%s nsid=%s (secid=%u)\n",
				__FUNCTION__, ssid->ctx, tsid->ctx, nsid->ctx, secid);
	return secid;
}

#define	mselinux_check_common(se,cookie,mcache,av_name)				\
	do {															\
		security_id_t	ssid;										\
		security_id_t	tsid;										\
		int				rc;											\
																	\
		ssid = (se)->server.core->get_engine_specific((cookie));	\
		tsid = (mcache)->tsid;										\
																	\
		pthread_rwlock_rdlock(&permissions.lock);					\
																	\
		rc = avc_has_perm(ssid, tsid,									\
						  permissions.tclass,							\
						  permissions.av_name,							\
						  NULL, mcache);								\
																		\
		pthread_rwlock_unlock(&permissions.lock);						\
																		\
		if ((se)->config.debug)											\
			fprintf(stderr, "%s: ssid=%s tsid=%s %s\n",					\
					__FUNCTION__, ssid->ctx, tsid->ctx,					\
					!rc ? "allowed" : "denied");						\
																		\
		if (rc)															\
			return false;												\
	} while(0)

bool
mselinux_check_create(selinux_engine_t *se, const void *cookie,
					  mcache_t *mcache)
{
	if (se->config.selinux)
	{
		mselinux_check_common(se, cookie, mcache, create);
	}
	return true;
}

bool
mselinux_check_read(selinux_engine_t *se, const void *cookie,
					mcache_t *mcache)
{
	if (se->config.selinux)
	{
		mselinux_check_common(se, cookie, mcache, read);
	}
	return true;
}

bool
mselinux_check_write(selinux_engine_t *se, const void *cookie,
					 mcache_t *old_cache, mcache_t *new_cache)
{
	if (se->config.selinux)
	{
		if (strcmp(old_cache->tsid->ctx, new_cache->tsid->ctx) != 0)
			return false;

		mselinux_check_common(se, cookie, new_cache, write);
	}
	return true;
}

bool
mselinux_check_append(selinux_engine_t *se, const void *cookie,
					  mcache_t *old_cache, mcache_t *new_cache)
{
	if (se->config.selinux)
	{
		if (strcmp(old_cache->tsid->ctx, new_cache->tsid->ctx) != 0)
			return false;

		mselinux_check_common(se, cookie, new_cache, append);
	}
	return true;
}

bool
mselinux_check_remove(selinux_engine_t *se, const void *cookie,
					  mcache_t *mcache)
{
	if (se->config.selinux)
	{
		mselinux_check_common(se, cookie, mcache, remove);
	}
	return true;
}

bool
mselinux_check_calculate(selinux_engine_t *se, const void *cookie,
						 mcache_t *mcache)
{
	if (se->config.selinux)
	{
		mselinux_check_common(se, cookie, mcache, calculate);
	}
	return true;
}

bool
mselinux_check_relabel(selinux_engine_t *se, const void *cookie,
					   mcache_t *old_cache, mcache_t *new_cache)
{
	if (se->config.selinux)
	{
		if (security_check_context_raw(new_cache->tsid->ctx) < 0)
			return false;

		mselinux_check_common(se, cookie, old_cache, relabelfrom);
		mselinux_check_common(se, cookie, new_cache, relabelto);

		return true;
	}
	return false;
}

static void
mselinux_on_connect(const void *cookie,
					ENGINE_EVENT_TYPE type,
					const void *event_data,
					const void *cb_data)
{
	selinux_engine_t   *se = (selinux_engine_t *)cb_data;
	security_context_t	context;
	security_id_t		ssid;
	int					sockfd;

	sockfd = se->server.core->get_socket_fd(cookie);

	if (getpeercon_raw(sockfd, &context) < 0)
		context = "user_u:user_r:user_t:s0";

	if (avc_context_to_sid(context, &ssid) < 0)
		ssid = NULL;

	se->server.core->store_engine_specific(cookie, ssid);
}

/*
 * Userspace Access Vector Cache
 *
 *
 *
 *
 */
static void
mavc_log(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
mavc_audit(void *auditdata, security_class_t cls,
				   char *msgbuf, size_t msgbufsize)
{
	mcache_t   *mcache = auditdata;

	fprintf(stderr, "%s key=%.*s\n", msgbuf,
			(int)mcache_get_keylen(mcache),
			(char *)mcache_get_key(mcache));
}

static struct avc_log_callback avc_log_cb = {
	.func_log			= mavc_log,
	.func_audit			= mavc_audit,
};

static void *
mavc_alloc_lock(void)
{
	pthread_mutex_t	   *lock = malloc(sizeof(pthread_mutex_t));

	//assert(lock != NULL);

	pthread_mutex_init(lock, NULL);

	return lock;
}

static void
mavc_get_lock(void *lock)
{
	pthread_mutex_lock((pthread_mutex_t *)lock);
}

static void
mavc_release_lock(void *lock)
{
	pthread_mutex_unlock((pthread_mutex_t *)lock);
}

static void
mavc_free_lock(void *lock)
{
	free(lock);
}

static struct avc_lock_callback avc_lock_cb = {
	.func_alloc_lock	= mavc_alloc_lock,
	.func_get_lock		= mavc_get_lock,
	.func_release_lock	= mavc_release_lock,
	.func_free_lock		= mavc_free_lock,
};

static int
mavc_cb_policyload(int seqno)
{
	security_class_t	tclass;

	pthread_rwlock_wrlock(&permissions.lock);

	tclass = string_to_security_class("kv_item");

	permissions.tclass		= tclass;
	permissions.create		= string_to_av_perm(tclass, "create");
	permissions.getattr		= string_to_av_perm(tclass, "getattr");
	permissions.setattr		= string_to_av_perm(tclass, "setattr");
	permissions.remove		= string_to_av_perm(tclass, "remove");
	permissions.read		= string_to_av_perm(tclass, "read");
	permissions.write		= string_to_av_perm(tclass, "write");
	permissions.append		= string_to_av_perm(tclass, "append");
	permissions.calculate	= string_to_av_perm(tclass, "calculate");
	permissions.relabelfrom	= string_to_av_perm(tclass, "relabelfrom")
							| string_to_av_perm(tclass, "setattr");
	permissions.relabelto	= string_to_av_perm(tclass, "relabelto");

	pthread_rwlock_unlock(&permissions.lock);

	return 0;
}

static void *
mavc_netlink_worker(void *data)
{
	int		sockfd;

	fprintf(stderr, "%s: worker thread was launched\n", __FUNCTION__);

	sockfd = avc_netlink_acquire_fd();

	avc_netlink_loop();

	avc_netlink_release_fd();

	fprintf(stderr, "%s: worker thread was terminated\n", __FUNCTION__);

	return NULL;
}

bool
mselinux_init(selinux_engine_t *se)
{
	union selinux_callback	selinux_cb;

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
	 * Memcached callback
	 */
	se->server.callback->register_callback((ENGINE_HANDLE *)se,
										   ON_CONNECT,
										   mselinux_on_connect, se);
	/*
	 * Set up userspace access vector
	 */
	if (avc_init(NULL,
				 NULL,
				 &avc_log_cb,
				 NULL,
				 &avc_lock_cb) < 0)
		return false;

	selinux_cb.func_policyload = mavc_cb_policyload;
	selinux_set_callback(SELINUX_CB_POLICYLOAD, selinux_cb);

	mavc_cb_policyload(0);

	if (pthread_create(&se->thread, NULL,
					   mavc_netlink_worker, NULL) != 0)
	{
		avc_destroy();
		return false;
	}
	return true;
}

void
mselinux_fini(selinux_engine_t *se)
{
	if (!se->config.selinux)
		return;

	if (se->thread > 0)
	{
		pthread_kill(se->thread, SIGKILL);
		pthread_join(se->thread, NULL);
	}
	avc_destroy();
}
