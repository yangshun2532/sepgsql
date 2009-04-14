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

#include "apr_strings.h"
#include "ap_mpm.h"

#define CORE_PRIVATE
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "scoreboard.h"

#include <selinux/selinux.h>
#include <selinux/context.h>

typedef struct
{
    char *dirname;
    char *config_file;
    char *default_domain;
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
 * selinux_post_read_request
 *
 *   It disables the contents caches implemented on quick_handler,
 *   because it enables to bypass access controls.
 */
static int selinux_post_read_request(request_rec *r)
{
    selinux_config *sconf
        = ap_get_module_config(r->per_dir_config,
                               &selinux_module);
    /*
     * If mod_selinux is available on the given request,
     * it does not allow to cache the contents to keep
     * consistency of access controls.
     */
    if (sconf && is_selinux_enabled() == 1)
        r->no_cache = 1;

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
    char *entry = NULL;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &selinux_module);
    if (!sconf)
        return DECLINED;

    if (is_selinux_enabled() < 1)
        return DECLINED;

    /*
     * Is there any matched entry or default domain
     * configured? If not, this module does not anything.
     */
    if (sconf->config_file)
        entry = selinux_lookup_entry(r, sconf->config_file);
    if (!entry)
        entry = apr_pstrdup(r->pool, sconf->default_domain);
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
        new_context = (security_context_t )apr_table_get(r->notes,
                                                         "auth-security-context");
        if (!new_context) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, r,
                          "No SELinux aware authentication module");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        context_t context;
        char *domain = entry;
        char *range = NULL;

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
        freecon(tmp_context);
    }

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
 * selinux_process_request
 *
 *   It is an entry point to invoke ap_process_request()
 *   in a separate worker thread.
 */
static void * APR_THREAD_FUNC
selinux_process_request(apr_thread_t *thd, void *datap)
{
    request_rec *r = datap;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "selinux: one-time-thread launched for uri=%s", r->uri);

    ap_process_request(r);

    apr_thread_exit(thd, 0);

    return NULL;
}

/*
 * selinux_process_connection
 *
 *   It overrides the default process_connection behavior, and
 *   launches a one-time worker thread for each requests.
 *   It enables selinux_fixups() to assign individual restrictive
 *   privileges prior to invocations of contents handlers.
 */
static int selinux_process_connection(conn_rec *c)
{
    /*
     * copied from ap_process_http_connection()
     */
    request_rec *r;
    apr_socket_t *csd = NULL;

    /*
     * Read and process each request found on our connection
     * until no requests are left or we decide to close.
     */

    ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);
    while ((r = ap_read_request(c)) != NULL) {

        c->keepalive = AP_CONN_UNKNOWN;
        /* process the request if it was read without error */

        ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
        if (r->status == HTTP_OK)
        {
            apr_thread_t *thread;
            apr_status_t rv, threadrv;

            rv = apr_thread_create(&thread, NULL,
                                   selinux_process_request,
                                   r, r->pool);
            if (rv != APR_SUCCESS) {
                ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
                break;
            }

            rv = apr_thread_join(&threadrv, thread);
            if (rv != APR_SUCCESS) {
                ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
                break;
            }
        }

        if (ap_extended_status)
            ap_increment_counts(c->sbh, r);

        if (c->keepalive != AP_CONN_KEEPALIVE || c->aborted)
            break;

        ap_update_child_status(c->sbh, SERVER_BUSY_KEEPALIVE, r);
        apr_pool_destroy(r->pool);

        if (ap_graceful_stop_signalled())
            break;

        if (!csd) {
            csd = ap_get_module_config(c->conn_config, &core_module);
        }
        apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 1);
        apr_socket_timeout_set(csd, c->base_server->keep_alive_timeout);
        /* Go straight to select() to wait for the next request */
    }

    return OK;
}

static void selinux_hooks(apr_pool_t *p)
{
    ap_hook_process_connection(selinux_process_connection,
                               NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(selinux_post_read_request,
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
    sconf->config_file = NULL;
    sconf->default_domain = NULL;

    return sconf;
}

static const char *set_config_file(cmd_parms *cmd,
								   void *mconfig, const char *v1)
{
    selinux_config *sconf
        = ap_get_module_config(cmd->context, &selinux_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinux: selinuxConfigFile = %s at %s",
                 v1, sconf->dirname);

    sconf->config_file = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *set_default_domain(cmd_parms *cmd,
                                      void *mconfig, const char *v1)
{
    selinux_config *sconf
        = ap_get_module_config(cmd->context, &selinux_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinux: selinuxDefaultDomain = %s at %s",
                 v1, sconf->dirname);

    sconf->default_domain = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const command_rec selinux_cmds[] = {
    AP_INIT_TAKE1("selinuxConfigFile",
                  set_config_file, NULL, OR_OPTIONS,
                  "Apache/SELinux plus configuration file"),
    AP_INIT_TAKE1("selinuxDefaultDomain",
                  set_default_domain, NULL, OR_OPTIONS,
                  "Apache/SELinux plus default security context"),
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
