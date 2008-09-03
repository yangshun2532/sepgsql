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
#include "ap_config.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include <selinux/selinux.h>

typedef struct selinux_entry
{
    struct selinux_entry *next;

    char *name;
    /* name == NULL means default setting */

    char *domain;
    char *range;
} selinux_entry;

typedef struct selinux_config
{
    char *dirname;

    selinux_entry *users_list;
} selinux_config;

/*
 * Forward declaration
 */
module AP_MODULE_DECLARE_DATA auth_selinux_module;


/*
 * auth_selinux_post_config
 *
 * SELinux awared Apache MPM does not allow to enable KeepAlive mode,
 */
static int auth_selinux_post_config(apr_pool_t *pconf, apr_pool_t *plog,
			     apr_pool_t *ptemp, server_rec *s)
{
    if (s->keep_alive) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
		     "SELinux awared MPM does not allow to enable KeepAlive mode. ");
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    return OK;
}

static int auth_selinux_handler(request_rec *r)
{
    selinux_config *sconf = ap_get_module_config(r->per_dir_config,
						 &auth_selinux_module);
    selinux_entry *s, *match = NULL;
    security_context_t context;
    char *user, *role, *domain, *range;
    char buffer[1024];

    if (!sconf)
	return DECLINED;	/* do nothing */

    for (s = sconf->users_list; s; s = s->next) {
	if (!s->name)
	    match = s;
	else if (r->user && !strcmp(r->user, s->name)) {
	    match = s;
	    break;
	}
    }

    if (!match) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		     "No matched selinuxUserDomain/Range for %s. "
		     "Its/default entry should be added.",
		     r->user ? r->user : "anonymous");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (getcon_raw(&context) < 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		     "SELinux: getcon_raw() failed (%s)", strerror(errno));
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    user = strtok(context, ":");
    role   = strtok(NULL, ":");
    domain = strtok(NULL, ":");
    range  = strtok(NULL, "\0");

    if (range) {
	snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
		 user, role,
		 match->domain ? match->domain : domain,
		 match->range ? match->range : range);
    } else {
	snprintf(buffer, sizeof(buffer), "%s:%s:%s",
		 user, role,
		 match->domain ? match->domain : domain);
    }
    freecon(context);

    if (setcon((security_context_t) buffer) < 0) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		     "SELinux: setcon(%s) for user: %s failed (%s)",
		     buffer, r->user, strerror(errno));
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		 "SELinux: setcon(%s) for user: %s",
		 buffer, r->user);

    return DECLINED;
}

static void *auth_selinux_create_dir_config(apr_pool_t *p, char *dirname)
{
    selinux_config *sconf = apr_pcalloc(p, sizeof(selinux_config));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		 "SELinux: create dir config at %s", dirname);

    sconf->dirname = apr_pstrdup(p, dirname);
    sconf->users_list = NULL;

    return sconf;
}

static void *auth_selinux_merge_dir_config(apr_pool_t *p,
				    void *base_config, void *new_config)
{
    selinux_config *bconf = base_config;
    selinux_config *nconf = new_config;
    selinux_config *mconf;	/* merged config */
    selinux_entry *s, *t;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		 "SELinux: merge dir config base: %s, new: %s",
		 bconf->dirname, nconf->dirname);

    mconf = apr_pcalloc(p, sizeof(selinux_config));
    mconf->dirname = apr_pstrdup(p, nconf->dirname);
    mconf->users_list = NULL;

    /* copy base config */
    for (s = bconf->users_list; s; s = s->next) {
	t = apr_palloc(p, sizeof(selinux_entry));
	t->name   = (s->name ? apr_pstrdup(p, s->name) : NULL);
	t->domain = (s->domain ? apr_pstrdup(p, s->domain) : NULL);
	t->range  = (s->range  ? apr_pstrdup(p, s->range)  : NULL);

	t->next = mconf->users_list;
	mconf->users_list = t;
    }

    /* merge new config */
    for (s = nconf->users_list; s; s = s->next) {
	for (t = mconf->users_list; t; t = t->next) {
	    if ((!s->name && !t->name) ||
		(s->name && t->name && !strcmp(s->name, t->name))) {
		if (s->domain)
		    t->domain = apr_pstrdup(p, s->domain);
		if (s->range)
		    t->range = apr_pstrdup(p, s->range);
		break;
	    }
	}

	if (!t) {
	    t = apr_palloc(p, sizeof(selinux_entry));
	    t->name   = (s->name   ? apr_pstrdup(p, s->name)   : NULL);
	    t->domain = (s->domain ? apr_pstrdup(p, s->domain) : NULL);
	    t->range  = (s->range  ? apr_pstrdup(p, s->range)  : NULL);
	    t->next   = mconf->users_list;
	    mconf->users_list = t;
	}
    }

    return mconf;
}

static const char *auth_selinux_config_user_domain(cmd_parms *cmd, void *mconfig,
					    const char *v1, const char *v2)
{
    selinux_config *sconf
	= ap_get_module_config(cmd->context,
			       &auth_selinux_module);
    selinux_entry *s;
    const char *username = NULL;

    if (!!strcmp("__default__", v1))
	username = v1;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		 "SELinux: user=%s domain=%s dir=%s",
		 v1, v2, sconf->dirname);

    /* duplication check */
    for (s = sconf->users_list; s; s = s->next) {
	if ((!username && !s->name) ||
	    (username && s->name && !strcmp(username, s->name))) {
	    if (s->domain)
		return "duplicate selinuxUserDomain entries";
	    s->domain = apr_pstrdup(cmd->pool, v2);
	    return NULL;
	}
    }

    /* new entry */
    s = apr_pcalloc(cmd->pool, sizeof(selinux_entry));
    s->name   = username ? apr_pstrdup(cmd->pool, username) : NULL;
    s->domain = apr_pstrdup(cmd->pool, v2);
    s->range  = NULL;
    s->next   = sconf->users_list;
    sconf->users_list = s;

    return NULL;
}

static const char *auth_selinux_config_user_range(cmd_parms *cmd, void *mconfig,
					   const char *v1, const char *v2)
{
    selinux_config *sconf
	= ap_get_module_config(cmd->context,
			       &auth_selinux_module);
    selinux_entry *s;
    const char *username = NULL;

    if (!!strcmp("__default__", v1))
	username = v1;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		 "SELinux: user=%s range=%s dir=%s",
		 v1, v2, sconf->dirname);

    /* duplication check */
    for (s = sconf->users_list; s; s = s->next) {
	if ((!username && !s->name) ||
	    (username && s->name && !strcmp(username, s->name))) {
	    if (s->range)
		return "duplicate selinuxUserRange entries";
	    s->range = apr_pstrdup(cmd->pool, v2);
	    return NULL;
	}
    }

    /* new entry */
    s = apr_pcalloc(cmd->pool, sizeof(selinux_entry));
    s->name   = username ? apr_pstrdup(cmd->pool, username) : NULL;
    s->domain = NULL;
    s->range  = apr_pstrdup(cmd->pool, v2);
    s->next   = sconf->users_list;
    sconf->users_list = s;

    return NULL;
}

static void auth_selinux_register_hooks(apr_pool_t *p)
{
    /*
     * SELinux awared Apache MPM requires to invoke set per-request
     * domain/range hooks at the top of contains handler.
     */
    ap_hook_post_config(auth_selinux_post_config,
			NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_handler(auth_selinux_handler,
		    NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static const command_rec auth_selinux_cmds[] = {
    AP_INIT_TAKE2("selinuxUserDomain",
		  auth_selinux_config_user_domain,
		  NULL, OR_OPTIONS,
		  "set per user domain of contains handler"),
    AP_INIT_TAKE2("selinuxUserRange",
		  auth_selinux_config_user_range,
		  NULL, OR_OPTIONS,
		  "set per user range of contains handler"),
    {NULL},
};

module AP_MODULE_DECLARE_DATA auth_selinux_module =
{
    STANDARD20_MODULE_STUFF,
    auth_selinux_create_dir_config,	/* create per-directory config */
    auth_selinux_merge_dir_config,	/* merge per-directory config */
    NULL,				/* server config creator */
    NULL,				/* server config merger */
    auth_selinux_cmds,			/* command table */
    auth_selinux_register_hooks,	/* set up other request processing hooks */
};
