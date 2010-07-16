/*
 * selinux.c
 *
 * access control facilities
 */
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include "selinux_engine.h"

static struct {
	pthread_rwlock_t	lock;
	security_class_t	tclass;
	access_vector_t		create;
	access_vector_t		getattr;
	access_vector_t		setattr;
	access_vector_t		drop;
	access_vector_t		read;
	access_vector_t		write;
	access_vector_t		append;
} permissions = {
	.lock				= PTHREAD_RWLOCK_INITIALIZER,
};

uint32_t
mselinux_check_alloc(selinux_engine_t *se, const void *cookie,
					 const void *key, size_t keylen)
{
	static security_id_t	tsid = NULL;
	security_id_t	ssid;
	security_id_t	nsid;
	uint32_t		secid;

	if (!se->config.selinux)
		return 0;

	ssid = se->server.core->get_engine_specific(cookie);
	if (!tsid)
		avc_context_to_sid_raw("system_u:object_r:sepgsql_db_t:s0", &tsid);

	pthread_rwlock_rdlock(&permissions.lock);

	avc_compute_create(ssid, tsid, permissions.tclass, &nsid);

	pthread_rwlock_unlock(&permissions.lock);

	secid = mlabel_get(se, nsid->ctx);

	if (se->config.debug)
		fprintf(stderr, "%s: ssid=%s tsid=%s nsid=%s (secid=%u)\n",
				__FUNCTION__, ssid->ctx, tsid->ctx, nsid->ctx, secid);
	return secid;
}

bool
mselinux_check_create(selinux_engine_t *se, const void *cookie,
					  mcache_t *mcache)
{
	security_id_t	ssid;
	security_id_t	tsid;
	int				rc;

	if (!se->config.selinux)
		return true;

	ssid = se->server.core->get_engine_specific(cookie);
	tsid = mcache->tsid;

	pthread_rwlock_rdlock(&permissions.lock);

	rc = avc_has_perm(ssid, tsid,
					  permissions.tclass,
					  permissions.create,
					  NULL, mcache);

	pthread_rwlock_unlock(&permissions.lock);

	if (se->config.debug)
		fprintf(stderr, "%s: ssid=%s tsid=%s {create} => %s\n",
				__FUNCTION__, ssid->ctx, tsid->ctx, !rc ? "allowed" : "denied");

	return !rc ? true : false;
}

bool
mselinux_check_read(selinux_engine_t *se, const void *cookie,
					mcache_t *mcache)
{
	security_id_t	ssid;
	security_id_t	tsid;
	int				rc;

	if (!se->config.selinux)
		return true;

	ssid = se->server.core->get_engine_specific(cookie);
	tsid = mcache->tsid;

	pthread_rwlock_rdlock(&permissions.lock);

	rc = avc_has_perm(ssid, tsid,
					  permissions.tclass,
					  permissions.read,
					  NULL, mcache);

	pthread_rwlock_unlock(&permissions.lock);

	if (se->config.debug)
		fprintf(stderr, "%s: ssid=%s tsid=%s {read} => %s\n",
				__FUNCTION__, ssid->ctx, tsid->ctx, !rc ? "allowed" : "denied");

	return !rc ? true : false;
}

bool
mselinux_check_write(selinux_engine_t *se, const void *cookie,
					 mcache_t *old_cache, mcache_t *new_cache)
{
	security_id_t	ssid;
	security_id_t	tsid;
	int				rc;

	if (!se->config.selinux)
		return true;

	if (strcmp(old_cache->tsid->ctx, new_cache->tsid->ctx) != 0)
		return false;

	ssid = se->server.core->get_engine_specific(cookie);
	tsid = new_cache->tsid;

	pthread_rwlock_rdlock(&permissions.lock);

	rc = avc_has_perm(ssid, tsid,
					  permissions.tclass,
					  permissions.write,
					  NULL, new_cache);

	pthread_rwlock_unlock(&permissions.lock);

	if (se->config.debug)
		fprintf(stderr, "%s: ssid=%s tsid=%s {write} => %s\n",
				__FUNCTION__, ssid->ctx, tsid->ctx, !rc ? "allowed" : "denied");

	return !rc ? true : false;
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

	fprintf(stderr, "%s\n",	msgbuf);
	//(int)mcache_get_keylen(mcache),
	//(char *)mcache_get_key(mcache));
}

static struct avc_log_callback avc_log_cb = {
	.func_log			= mavc_log,
	.func_audit			= mavc_audit,
};

static void *
mavc_alloc_lock(void)
{
	static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;

	return &lock;
}

static void
mavc_get_lock(void *lock)
{
	//pthread_mutex_lock((pthread_mutex_t *)lock);
}

static void
mavc_release_lock(void *lock)
{
	//pthread_mutex_unlock((pthread_mutex_t *)lock);
}

static void
mavc_free_lock(void *lock)
{
	/* do nothing */
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

	tclass = string_to_security_class("db_blob");

	permissions.tclass	= tclass;
	permissions.create	= string_to_av_perm(tclass, "create");
	permissions.getattr	= string_to_av_perm(tclass, "getattr");
	permissions.setattr	= string_to_av_perm(tclass, "setattr");
	permissions.drop	= string_to_av_perm(tclass, "drop");
	permissions.read	= string_to_av_perm(tclass, "read");
	permissions.write	= string_to_av_perm(tclass, "write");
	permissions.append	= string_to_av_perm(tclass, "append");

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
	se->server.callback->register_callback(ON_CONNECT, mselinux_on_connect, se);

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
