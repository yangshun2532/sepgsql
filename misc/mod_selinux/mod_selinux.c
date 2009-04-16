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

typedef struct
{
    char *dirname;
    char *mapping_file;
    char *default_context;
    int   allow_caches;
    int   allow_keep_alive;
} selinux_config;

module AP_MODULE_DECLARE_DATA selinux_module;

/*
 * selinux_lookup_entry
 *
 *   It lookups a matched entry from the given configuration file,
 *   and returns it as a cstring allocated on r->pool, if found.
 *   Otherwise, it returns NULL.
 */
static char *
selinux_lookup_entry(request_rec *r, const char *filename)
{
    const char *white_space = " \t\r\n";
    ap_configfile_t *filp;
    char buffer[MAX_STRING_LEN];
    apr_status_t status;
    char *ident, *entry, *mask, *pos;
    apr_ipsubnet_t *ipsub;
    int negative, lineno = 0;

    status = ap_pcfg_openfile(&filp, r->pool, filename);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, LOG_WARNING, status, r,
                      "Unable to open: %s", filename);
        return NULL;
    }

    while (ap_cfg_getline(buffer, sizeof(buffer), filp) == 0) {
        negative = 0;
        lineno++;

        /* skip empty line */
        pos = strchr(buffer, '#');
        if (pos)
            *pos = '\0';

        ident = strtok_r(buffer, white_space, &pos);
        if (!ident)
            continue;

        /* if the line begins with '!', it means negative. */
        if (*ident == '!') {
            ident++;
            negative = 1;
        }

        /* fetch domain and range */
        entry = strtok_r(NULL, white_space, &pos);
        if (!entry || strtok_r(NULL, white_space, &pos)) {
            ap_log_rerror(APLOG_MARK, LOG_WARNING, 0, r,
                          "syntax error at %s:%d", filename, lineno);
            continue;
        }

        /* ident is network address? or username? */
        mask = strchr(ident, '/');
        if (mask)
            *mask++ = '\0';

        if (apr_ipsubnet_create(&ipsub, ident, mask, r->pool) == APR_SUCCESS) {
            if (apr_ipsubnet_test(ipsub, r->connection->remote_addr)) {
                if (!negative)
                    goto found;
            } else if (negative)
                goto found;
        }
        else if (r->user) {
            if (mask)
                *--mask = '/';  /* fixup assumption of network address */
            if (strcmp(r->user, ident) == 0) {
                if (!negative)
                    goto found;
            } else if (negative)
                goto found;
        }
    }
    /* not found */
    ap_cfg_closefile(filp);
    return NULL;

found:
    ap_cfg_closefile(filp);
    return apr_pstrdup(r->pool, entry);
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
 * selinux_fixups
 *
 *   It assigns an appropriate security context on the current
 *   working thread based on attributes of the given request.
 */
static int selinux_fixups(request_rec *r)
{
    selinux_config *sconf;
    security_context_t old_context;
    security_context_t new_context;
    security_context_t tmp_context;
    context_t context;
    const char *entry = NULL;
    char *domain, *range;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &selinux_module);
    if (!sconf)
        return DECLINED;

    /*
     * Is there any matched entry or default domain
     * configured? If not, this module does not anything.
     */
    if (sconf->mapping_file)
        entry = selinux_lookup_entry(r, sconf->mapping_file);
    if (!entry)
        entry = sconf->default_context;
    if (!entry)
        return DECLINED;  /* no matched and default domain */

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
    if (!strcasecmp(entry, "auth-module")) {
        entry = apr_table_get(r->notes, "auth-security-context");
        if (!entry) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                          "No \"auth-security-context\" setting");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    domain = apr_pstrdup(r->pool, entry);
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

#ifndef WITH_MPM_SECURITY

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
#endif /* WITH_MPM_SECURITY */

/* ****************************************
 * Apache/SELinux plus API routines
 */
static void selinux_hooks(apr_pool_t *p)
{
	if (is_selinux_enabled() < 1)
		return;

#ifndef WITH_MPM_SECURITY
	ap_hook_process_connection(selinux_process_connection,
							   NULL, NULL, APR_HOOK_FIRST);
#endif
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
	sconf->mapping_file = NULL;
	sconf->default_context = NULL;
	sconf->allow_caches = 0;
    sconf->allow_keep_alive = 0;

    return sconf;
}

static const char *
set_mapping_file(cmd_parms *cmd, void *mconfig, const char *v1)
{
	selinux_config *sconf
		= ap_get_module_config(cmd->context, &selinux_module);

	sconf->mapping_file = apr_pstrdup(cmd->pool, v1);

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
				 "selinuxMappingFile = '%s' at '%s'",
				 v1, sconf->dirname);
	return NULL;
}

static const char *
set_default_context(cmd_parms *cmd, void *mconfig, const char *v1)
{
	selinux_config *sconf
		= ap_get_module_config(cmd->context, &selinux_module);

	sconf->default_context = apr_pstrdup(cmd->pool, v1);

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
				 "selinuxDefaultContext = '%s' at '%s'",
				 v1, sconf->dirname);
	return NULL;
}

static const char *
set_allow_caches(cmd_parms *cmd, void *mconfig, int flag)
{
    selinux_config *sconf
        = ap_get_module_config(cmd->context, &selinux_module);

    sconf->allow_caches = flag;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinuxForceCacheDisable = %s at '%s'",
                 flag ? "On" : "Off", sconf->dirname);
    return NULL;
}

static const char *
set_allow_keep_alive(cmd_parms *cmd, void *mconfig, int flag)
{
    selinux_config *sconf
        = ap_get_module_config(cmd->context, &selinux_module);

    sconf->allow_keep_alive = flag;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinuxForceKeepAliveDisable = %s at '%s'",
                 flag ? "On" : "Off", sconf->dirname);
    return NULL;
}

static const command_rec selinux_cmds[] = {
    AP_INIT_TAKE1("selinuxMappingFile",
                  set_mapping_file, NULL, OR_OPTIONS,
                  "Apache/SELinux plus mapping file"),
    AP_INIT_TAKE1("selinuxDefaultContext",
                  set_default_context, NULL, OR_OPTIONS,
                  "Apache/SELinux plus default security context"),
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
