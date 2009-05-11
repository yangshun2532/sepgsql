/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "httpd.h"

#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_thread_proc.h"
#include "ap_listen.h"
#include "ap_mpm.h"

#include "http_connection.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"

#include <unistd.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

#define SELINUX_MAP_CONTEXT     1
#define SELINUX_ENV_CONTEXT     2
#define SELINUX_SET_CONTEXT     3

typedef struct selinux_list selinux_list;
struct selinux_list
{
    selinux_list   *next;

    int             method;
    char            value[1];
};

typedef struct selinux_config selinux_config;
struct selinux_config
{
    const char     *dirname;
    selinux_list   *list;
    int             allow_caches;
    int             allow_keep_alive;
};

module AP_MODULE_DECLARE_DATA selinux_module;

/*
 * selinux_map_fixups
 *
 *   It lookups a matched entry from the given configuration file,
 *   and returns 1 with a copied cstring, if found. Otherwise, it returns 0.
 */
static int
selinux_map_fixups(request_rec *r, const char *filename, char **domain)
{
    const char *white_space = " \t\r\n";
    ap_configfile_t *filp;
    char buffer[MAX_STRING_LEN];
    apr_status_t status;
    char *user, *context, *pos;
    int lineno = 0;

    status = ap_pcfg_openfile(&filp, r->pool, filename);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, LOG_WARNING, status, r,
                      "Unable to open: %s", filename);
        return -1;
    }

    while (ap_cfg_getline(buffer, sizeof(buffer), filp) == 0) {
        lineno++;

        /* skip empty line */
        pos = strchr(buffer, '#');
        if (pos)
            *pos = '\0';

        user = strtok_r(buffer, white_space, &pos);
        if (!user)
            continue;
        context = strtok_r(NULL, white_space, &pos);
        if (!context || strtok_r(NULL, white_space, &pos)) {
            ap_log_rerror(APLOG_MARK, LOG_WARNING, 0, r,
                          "syntax error at %s:%d", filename, lineno);
            continue;
        }

        if (!strcmp(user, "*") ||
            (r->user && !strcmp(user, r->user)) ||
            (!r->user && !strcmp(user, "__anonymous__")))
        {
            *domain = apr_pstrdup(r->pool, context);
            ap_cfg_closefile(filp);

            return 1;
        }
    }
    /* not found */
    ap_cfg_closefile(filp);
    return 0;
}

/*
 * selinux_env_fixups
 *
 *   It returns 1 and copies the required environment variable to the
 *   caller, if it is already defined. Otherwise, it returns 0.
 */
static int
selinux_env_fixups(request_rec *r, const char *envname, char **domain)
{
    const char *envval
        = apr_table_get(r->subprocess_env, envname);

    if (envval) {
        *domain = apr_pstrdup(r->pool, envval);
        return 1;
    }
    return 0;
}

/*
 * selinux_set_fixups
 *
 *   It always returns 1 and a copy of the given context. We can use
 *   it as a default when map/env cannot find any entries.
 */
static int
selinux_set_fixups(request_rec *r, const char *context, char **domain)
{
    *domain = apr_pstrdup(r->pool, context);
    return 1;
}

/*
 * selinux_fixups
 *
 *   It assigns an appropriate security context on the current
 *   working thread based on attributes of the given request.
 */
static int selinux_fixups(request_rec *r)
{
    security_context_t old_context;
    security_context_t new_context;
    security_context_t tmp_context;
    context_t          context;
    selinux_config *sconf;
    selinux_list   *entry;
    char           *domain, *range;
    int             rc = 0;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &selinux_module);
    if (!sconf || !sconf->list)
        return DECLINED;

    for (entry = sconf->list; !rc && entry; entry = entry->next)
    {
        switch (entry->method)
        {
        case SELINUX_MAP_CONTEXT:
            rc = selinux_map_fixups(r, entry->value, &domain);
            break;
        case SELINUX_ENV_CONTEXT:
            rc = selinux_env_fixups(r, entry->value, &domain);
            break;
        default: /* SELINUX_SET_CONTEXT */
            rc = selinux_set_fixups(r, entry->value, &domain);
            break;
        }

        if (rc < 0)
            return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* no matched entry */
    if (rc == 0)
        return DECLINED;

    /*
     * Get the current security context
     */
    if (getcon_raw(&tmp_context) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, r->server,
                     "SELinux: getcon_raw() failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    old_context = apr_pstrdup(r->pool, tmp_context);
    freecon(tmp_context);

    /*
     * Compute a new security context
     */
    range = strchr(domain, ':');
    if (range)
        *range++ = '\0';

    context = context_new(old_context);
    if (!context) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                      "context_new('%s') failed", old_context);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (domain && strcmp(domain, "*") != 0)
        context_type_set(context, domain);
    if (range  && strcmp(range, "*") != 0)
        context_range_set(context, range);

    tmp_context = context_str(context);
    if (!tmp_context) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                      "context_str() failed");
        context_free(context);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    new_context = apr_pstrdup(r->pool, tmp_context);
    context_free(context);

    /*
     * If old_context == new_context, we don't need to do anything.
     */
    if (strcmp(old_context, new_context) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "no need to set security context: %s "
                      "(uri=%s dir=%s user=%s remote=%s)",
                      old_context,
                      r->uri, sconf->dirname, r->user,
                      r->connection->remote_ip);
        return DECLINED;
    }

    if (setcon_raw(new_context) < 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                      "setcon_raw('%s') failed", new_context);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "set security context: %s -> %s "
                  "(uri=%s dir=%s user=%s remote=%s)",
                  old_context, new_context,
                  r->uri, sconf->dirname, r->user,
                  r->connection->remote_ip);
    return DECLINED;
}

/*
 * selinux_disable_cache
 *   It disables contents caches, if not allowed explicitly.
 */
static int selinux_disable_cache(request_rec *r)
{
    selinux_config *sconf
        = ap_get_module_config(r->per_dir_config, &selinux_module);

    if (sconf && !sconf->allow_caches)
        r->no_cache = 1;

    return DECLINED;
}

/*
 * selinux_disable_keep_alive
 *   It disables keep-alive connection, if not allowed explicitly.
 */
static int selinux_disable_keep_alive(request_rec *r)
{
    selinux_config *sconf
        = ap_get_module_config(r->per_dir_config, &selinux_module);

    if (sconf && !sconf->allow_keep_alive)
        r->connection->keepalive = AP_CONN_CLOSE;

    return DECLINED;
}

/*
 * selinux_process_connection
 *
 *   It overrides the default handler (ap_process_http_connection)
 *   and launches a one-time thread to invoke the default one.
 */
static int __thread volatile is_worker = 0;

static void * APR_THREAD_FUNC
selinux_worker_process_connection(apr_thread_t *thread, void *dummy)
{
    conn_rec *c = (conn_rec *) dummy;

    /* marks as the current context is worker thread */
    is_worker = 1;

    ap_run_process_connection(c);

    apr_thread_exit(thread, 0);

    return NULL;
}

static int selinux_process_connection(conn_rec *c)
{
    apr_threadattr_t *thread_attr;
    apr_thread_t *thread;
    apr_status_t rv, thread_rv;

    /*
     * If the hook is invoked under the worker context,
     * we simply skips it.
     */
    if (is_worker)
        return DECLINED;

    apr_threadattr_create(&thread_attr, c->pool);
    /* 0 means PTHREAD_CREATE_JOINABLE */
    apr_threadattr_detach_set(thread_attr, 0);

    rv = apr_thread_create(&thread, thread_attr,
                           selinux_worker_process_connection,
                           c, c->pool);
    if (rv != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, errno, c,
                      "Unable to launch a one-time thread");
        c->aborted = 1;
        return DONE;
    }

    rv = apr_thread_join(&thread_rv, thread);
    if (rv != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, errno, c,
                      "Unable to join the worker thread");
        c->aborted = 1;
        return DONE;
    }

    return OK;
}

/* ---------------------------------------
 * Apache/SELinux plus API routines
 */
static void selinux_hooks(apr_pool_t *p)
{
	if (is_selinux_enabled() < 1)
		return;

	ap_hook_process_connection(selinux_process_connection,
							   NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_read_request(selinux_disable_cache,
							  NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_log_transaction(selinux_disable_keep_alive,
							NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_fixups(selinux_fixups, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *selinux_create_dir(apr_pool_t *p, char *dirname)
{
    selinux_config *sconf
        = apr_pcalloc(p, sizeof(selinux_config));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "selinux: create dir config at %s", dirname);

    sconf->dirname = apr_pstrdup(p, dirname);
    sconf->list = NULL;
	sconf->allow_caches = 0;
    sconf->allow_keep_alive = 0;

    return sconf;
}

static const char *
set_method_context(cmd_parms *cmd, void *mconfig,
                   int method, const char *v1)
{
    selinux_config *sconf = mconfig;
    selinux_list   *entry, *cur;

    entry = apr_palloc(cmd->pool, sizeof(selinux_list) + strlen(v1));
    entry->next = NULL;
    entry->method = method;
    strcpy(entry->value, v1);

    if (!sconf->list)
    {
        sconf->list = entry;
        return NULL;
    }

    for (cur = sconf->list; cur->next; cur = cur->next);

    cur->next = entry;

    return NULL;
}

static const char *
set_map_context(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return set_method_context(cmd, mconfig, SELINUX_MAP_CONTEXT, v1);
}

static const char *
set_env_context(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return set_method_context(cmd, mconfig, SELINUX_ENV_CONTEXT, v1);
}

static const char *
set_set_context(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return set_method_context(cmd, mconfig, SELINUX_SET_CONTEXT, v1);
}

static const char *
set_allow_caches(cmd_parms *cmd, void *mconfig, int flag)
{
    selinux_config *sconf = mconfig;

    sconf->allow_caches = flag;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinuxAllowCaches = %s at '%s'",
                 flag ? "On" : "Off", sconf->dirname);
    return NULL;
}

static const char *
set_allow_keep_alive(cmd_parms *cmd, void *mconfig, int flag)
{
    selinux_config *sconf = mconfig;

    sconf->allow_keep_alive = flag;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinuxAllowKeepAlive = %s at '%s'",
                 flag ? "On" : "Off", sconf->dirname);
    return NULL;
}

static const command_rec selinux_cmds[] = {
    AP_INIT_TAKE1("selinuxMapContext",
                  set_map_context, NULL, OR_OPTIONS,
                  "Set the security context using user/group mapping file"),
    AP_INIT_TAKE1("selinuxEnvContext",
                  set_env_context, NULL, OR_OPTIONS,
                  "Set the security context using environment variable"),
    AP_INIT_TAKE1("selinuxSetContext",
                  set_set_context, NULL, OR_OPTIONS,
                  "Set the security context to perform"),
    AP_INIT_FLAG("selinuxAllowCaches",
                 set_allow_caches, NULL, OR_OPTIONS,
                 "Enables to control availability of contents caches"),
    AP_INIT_FLAG("selinuxAllowKeepAlive",
                 set_allow_keep_alive, NULL, OR_OPTIONS,
                 "Enables to control availability of keep-alive connection"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA selinux_module = {
    STANDARD20_MODULE_STUFF,
    selinux_create_dir,     /* create per-directory config */
    NULL,                   /* merge per-directory config */
    NULL,                   /* server config creator */
    NULL,                   /* server config merger */
    selinux_cmds,           /* command table */
    selinux_hooks,          /* set up other hooks */
};
