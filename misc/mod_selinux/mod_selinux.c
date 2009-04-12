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
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "scoreboard.h"

#include <selinux/selinux.h>
#include <selinux/context.h>

struct selinux_config_t
{
    const char *dirname;
    const char *map_file;
    const char *default_domain;
};
typedef struct selinux_config_t selinux_config;

module AP_MODULE_DECLARE_DATA selinux_module;

static char *selinux_lookup_entry(request_rec *r, const char *filename)
{
    const char *white_space = " \t\n\r";
    char buffer[1024], *ident, *entry, *mask, *tmp;
    int negative, lineno = 0;
    apr_ipsubnet_t *ipsub;
    FILE *filp;

    filp = fopen(filename, "rb");
    if (!filp) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, r->server,
                     "selinux: unable to open map file: %s",
                     strerror(errno));
        return NULL;
    }

    while (fgets(buffer, sizeof(buffer), filp))
    {
        negative = 0;

        tmp = strchr(buffer, '#');
        if (tmp)
            *tmp = '\0';

        ident = strtok_r(buffer, white_space, &tmp);
        if (!ident)
            continue;

        if (*ident == '!') {
            ident++;
            negative = 1;
        }

        entry = strtok_r(NULL, white_space, &tmp);
        if (!entry || strtok_r(NULL, white_space, &tmp))
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                         "syntax error at %s:%u", filename, lineno);
            continue;
        }

        mask = strchr(ident, '/');
        if (mask)
            *mask++ = '\0';

        if (apr_ipsubnet_create(&ipsub, ident, mask, r->pool) == APR_SUCCESS)
        {
            if (apr_ipsubnet_test(ipsub, r->connection->remote_addr))
            {
                if (!negative)
                    goto found;
            }
            else if (negative)
                goto found;
        }
        else if (r->user != NULL)
        {
            if (mask)
                *--mask = '/';  /* fixup identifier */
            if (strcmp(r->user, ident) == 0)
            {
                if (!negative)
                    goto found;
            }
            else if (negative)
                goto found;
        }
    }
    entry = NULL;   /* not found */

found:
    fclose(filp);

    if (entry)
        entry = apr_pstrdup(r->pool, entry);

    return entry;
}

static int selinux_fixup_context(request_rec *r, const char *entry)
{
    security_context_t newcon, oldcon;
    context_t context;
    char *domain, *range;

    domain = apr_pstrdup(r->pool, entry);
    range = strchr(domain, ':');
    if (range)
        *range++ = '\0';

    if (domain && !strcmp(domain, "*"))
        domain = NULL;
    if (range && !strcmp(range, "*"))
        range = NULL;

    if (getcon_raw(&oldcon) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, r->server,
                     "selinux: getcon_raw() failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    context = context_new(oldcon);
    if (!context)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, r->server,
                     "selinux: context_new() failed");
        freecon(oldcon);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (domain)
        context_type_set(context, domain);
    if (range)
        context_range_set(context, range);

    newcon = context_str(context);
    if (!newcon)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, r->server,
                     "selinux: context_str() failed");
        freecon(oldcon);
        context_free(context);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (setcon_raw(newcon) < 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, r->server,
                     "selinux: unable to translate security context: "
                     "%s -> %s (user: %s, remote: %s)",
                     oldcon, newcon, r->user, r->connection->remote_ip);
        freecon(oldcon);
        context_free(context);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "selinux: translate security context: "
                 "%s -> %s (user: %s, remote: %s)",
                 oldcon, newcon, r->user, r->connection->remote_ip);
    freecon(oldcon);
    context_free(context);

    return DECLINED;
}


static int selinux_fixups(request_rec *r)
{
    selinux_config *sconf;
    const char *entry = NULL;

    if (is_selinux_enabled() < 1)
        return DECLINED;

    sconf = ap_get_module_config(r->per_dir_config, &selinux_module);
    if (!sconf)
        return DECLINED;

    entry = selinux_lookup_entry(r, sconf->map_file);
    if (!entry)
        return DECLINED;

    return selinux_fixup_context(r, entry);
}

static void * APR_THREAD_FUNC
selinux_process_request(apr_thread_t *thd, void *datap)
{
    request_rec *r = datap;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "selinux: one-time-thread launched for "
                 "(uri:%s, user:%s, remote-ip:%s)",
                 r->uri, r->user, r->connection->remote_ip);

    ap_process_request(r);

    return NULL;
}

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
    ap_hook_fixups(selinux_fixups,
                   NULL, NULL, APR_HOOK_MIDDLE);
}

static void *selinux_create_dir(apr_pool_t *p, char *dirname)
{
    selinux_config *sconf
        = apr_pcalloc(p, sizeof(selinux_config));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "selinux: create dir config at %s", dirname);

    sconf->dirname = apr_pstrdup(p, dirname);
    sconf->map_file = NULL;
    sconf->default_domain = NULL;

    return sconf;
}

static const char *set_ident_map_file(cmd_parms *cmd,
                                      void *mconfig, const char *v1)
{
    selinux_config *sconf
        = ap_get_module_config(cmd->context, &selinux_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "selinux: selinuxIdentMapFile = %s at %s",
                 v1, sconf->dirname);

    sconf->map_file = apr_pstrdup(cmd->pool, v1);

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
    AP_INIT_TAKE1("selinuxIdentMapFile",
                  set_ident_map_file, NULL, OR_OPTIONS,
                  "Apache/SELinux plus identification map file"),
    AP_INIT_TAKE1("selinuxDefaultDomain",
                  set_default_domain, NULL, OR_OPTIONS,
                  "Apache/SELinux plus default domain/range"),
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
