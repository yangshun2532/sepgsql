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

typedef struct selinux_config
{
	char *dirname;
	char *conffile;
	int   available;
} selinux_config;

/*
 * Forward declaration
 */
module AP_MODULE_DECLARE_DATA selinux_auth_module;

/*
 * auth_selinux_post_config
 *
 * SELinux awared Apache MPM does not allow to enable KeepAlive mode,
 */
static int selinux_auth_post_config(apr_pool_t *pconf, apr_pool_t *plog,
				    apr_pool_t *ptemp, server_rec *serv)
{
	/* check the state of KeepAlive */
	if (serv->keep_alive) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, serv,
			     "Unable KeepAlive on httpd-selinux. "
			     "Please turn it off");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}

static int selinux_auth_handler(request_rec *r)
{
	selinux_config *sconf = ap_get_module_config(r->per_dir_config,
						     &selinux_auth_module);
	security_context_t context;
	const char *delim = " \t\r\n";
	char *ident, *user, *role, *domain, *range, *tmp;
	char buffer[1024], new_domain[512], new_range[512];
	FILE *filp;
	int match;

	if (!sconf || !sconf->available)
		return DECLINED;	/* do nothing */

	/*
	 * Parse configuration file
	 */
	filp = fopen(sconf->conffile, "rb");
	if (!filp)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: could not open %s (%s)",
			     sconf->conffile, strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	match = 0;
	while (fgets(buffer, sizeof(buffer), filp))
	{
		tmp = strchr(buffer, '#');
		if (tmp)
			*tmp = '\0';

		ident = strtok_r(buffer, delim, &tmp);
		if (!ident)
			continue;	/* empty line */

		if (!strcmp(ident, "__default__"))
			ident = NULL;

		domain = strtok_r(NULL, delim, &tmp);
		if (!domain || strtok_r(NULL, delim, &tmp))
		{
			fclose(filp);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				     "SELinux: syntax error at %s",
				     sconf->conffile);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		range = strchr(domain, ':');
		if (range) {
			*range = '\0';
			range++;
		}

		if (!ident || (r->user && !strcmp(r->user, ident)))
		{
			if (!domain || !strcmp(domain, "*"))
				new_domain[0] = '\0';
			else {
				strncpy(new_domain, domain, sizeof(new_domain));
				new_domain[sizeof(new_domain) - 1] = '\0';
			}

			if (!range || !strcmp(range, "*"))
				new_range[0] = '\0';
			else {
				strncpy(new_range, range, sizeof(new_range));
				new_range[sizeof(new_range) - 1] = '\0';
			}
			match = 1;

			if (ident)
				break;
		}
	}
	fclose(filp);

	if (!match)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: No matched user domain/range for %s",
			     r->user ? r->user : "anonymous");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * Set a new security context
	 */
	if (new_domain[0] == '\0' && new_range[0] == '\0')
		return DECLINED;	/* we need to do nothing */

	if (getcon_raw(&context) < 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: getcon_raw() failed (%s)",
			     strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	user	= strtok_r(context, ":", &tmp);
	role	= strtok_r(NULL, ":", &tmp);
	domain	= strtok_r(NULL, ":", &tmp);
	range	= strtok_r(NULL, "\0", &tmp);

	if (range) {
		snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s",
			 user, role,
			 new_domain[0] ? new_domain : domain,
			 new_range[0] ? new_range : range);
	}
	else
	{
		snprintf(buffer, sizeof(buffer), "%s:%s:%s",
			 user, role,
			 new_domain[0] ? new_domain : domain);
	}
	freecon(context);

	if (setcon((security_context_t) buffer) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: setcon(%s) for %s failed (%s)",
			     buffer,
			     r->user ? r->user : "anonymous",
			     strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		     "SELinux: setcon(%s) for %s",
		     buffer, r->user ? r->user : "anonymous");

	return DECLINED;
}

static void *selinux_auth_create_dir_config(apr_pool_t *p,
					    char *dirname)
{
	selinux_config *sconf = apr_pcalloc(p, sizeof(selinux_config));

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		     "SELinux: create dir config at %s", dirname);

	sconf->dirname = apr_pstrdup(p, dirname);
	sconf->conffile = NULL;
	sconf->available = 0;

	return sconf;
}

static void *selinux_auth_merge_dir_config(apr_pool_t *p,
					   void *base_config,
					   void *new_config)
{
	selinux_config *bconf = base_config;
	selinux_config *nconf = new_config;
	selinux_config *mconf;	/* merged config */

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		     "SELinux: merge dir config base: %s, new: %s",
		     bconf->dirname, nconf->dirname);

	mconf = apr_pcalloc(p, sizeof(selinux_config));
	mconf->dirname = apr_pstrdup(p, nconf->dirname);
	mconf->conffile = apr_pstrdup(p, nconf->conffile);
	mconf->available = nconf->available;

	return mconf;
}

static const char *set_auth_config_file(cmd_parms *cmd,
					void *mconfig,
					const char *v1)
{
	selinux_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_auth_module);

	if (!strcasecmp(v1, "none")) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
			     "selinuxAuthConfigFile = None for %s",
			     sconf->dirname);
		sconf->available = 0;
		sconf->conffile = NULL;
	} else {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
			     "selinuxAuthConfigFile = '%s' for %s",
			     v1, sconf->dirname);
		sconf->available = 1;
		sconf->conffile = apr_pstrdup(cmd->pool, v1);
	}

	return NULL;
}

static void selinux_auth_register_hooks(apr_pool_t *p)
{
	/*
	 * SELinux awared Apache MPM requires to invoke set per-request
	 * domain/range hooks at the top of contains handler.
	 */
	ap_hook_post_config(selinux_auth_post_config,
			    NULL, NULL, APR_HOOK_MIDDLE);

	ap_hook_handler(selinux_auth_handler,
			NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static const command_rec selinux_auth_cmds[] = {
	AP_INIT_TAKE1("selinuxAuthConfigFile",
		      set_auth_config_file, NULL, OR_OPTIONS,
		      "Apache/SELinux support with HTTP authentication"),
	{NULL},
};

module AP_MODULE_DECLARE_DATA selinux_auth_module =
{
	STANDARD20_MODULE_STUFF,
	selinux_auth_create_dir_config,	/* create per-directory config */
	selinux_auth_merge_dir_config,	/* merge per-directory config */
	NULL,				/* server config creator */
	NULL,				/* server config merger */
	selinux_auth_cmds,		/* command table */
	selinux_auth_register_hooks,	/* set up other hooks */
};
