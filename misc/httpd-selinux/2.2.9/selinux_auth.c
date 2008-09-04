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
#include <selinux/context.h>

typedef struct selinux_config
{
	char *dirname;

	char *config_file;
	char *default_domain;
	char *default_range;
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
	security_context_t security_context;
	context_t context;
	const char *delim = " \t\r\n";
	char *ident, *domain, *range, *tmp;
	char buffer[1024];
	FILE *filp;

	if (!sconf)
		return DECLINED;	/* do nothing */

	if (!sconf->config_file || !r->user)
		goto not_found;
	/*
	 * Parse configuration file
	 */
	filp = fopen(sconf->config_file, "rb");
	if (!filp)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: could not open %s (%s)",
			     sconf->config_file, strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	while (fgets(buffer, sizeof(buffer), filp))
	{
		tmp = strchr(buffer, '#');
		if (tmp)
			*tmp = '\0';

		ident = strtok_r(buffer, delim, &tmp);
		if (!ident)
			continue;	/* empty line */

		domain = strtok_r(NULL, delim, &tmp);
		if (!domain || strtok_r(NULL, delim, &tmp))
		{
			fclose(filp);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				     "SELinux: syntax error at %s",
				     sconf->config_file);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		range = strchr(domain, ':');
		if (range) {
			*range = '\0';
			range++;
		}

		if (!strcmp(r->user, ident))
		{
			if (domain && !strcmp(domain, "*"))
				domain = NULL;
			if (range && !strcmp(range, "*"))
				range = NULL;

			goto found;
		}
	}
	fclose(filp);

	/*
	 * If sconf->config_file does not contain required
	 * user entry, default ones are applied.
	 */
not_found:
	domain = sconf->default_domain;
	range  = sconf->default_range;

found:
	/*
	 * Set a new security context
	 */
	if (!domain && !range)
		return DECLINED;	/* No need to do anything */

	if (getcon_raw(&security_context) < 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: getcon_raw() failed (%s)",
			     strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	context = context_new(security_context);
	freecon(security_context);
	if (!context)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: context_new(%s) failed (%s)",
			     security_context, strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (domain)
		context_type_set(context, domain);
	if (range)
		context_range_set(context, range);

	security_context = context_str(context);
	context_free(context);
	if (!security_context)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: context_str() failed (%s)",
			     strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (setcon(security_context) < 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: setcon(%s) for %s failed (%s)",
			     security_context,
			     r->user ? r->user : "anonymous",
			     strerror(errno));
		freecon(security_context);

		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		     "SELinux: setcon(%s) for %s",
		     security_context,
		     r->user ? r->user : "anonymous");
	freecon(security_context);

	return DECLINED;
}

static void *selinux_auth_create_dir_config(apr_pool_t *p,
					    char *dirname)
{
	selinux_config *sconf = apr_pcalloc(p, sizeof(selinux_config));

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		     "SELinux: create dir config at %s", dirname);

	sconf->dirname = apr_pstrdup(p, dirname);
	sconf->config_file = NULL;
	sconf->default_domain = NULL;
	sconf->default_range = NULL;

	return sconf;
}

static const char *set_config_file(cmd_parms *cmd,
				   void *mconfig, const char *v1)
{
	selinux_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_auth_module);

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "selinuxAuthConfigFile = %s for %s",
		     v1, sconf->dirname);

	if (!strcasecmp(v1, "none"))
		sconf->config_file = NULL;
	else
		sconf->config_file = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_default_domain(cmd_parms *cmd,
				      void *mconfig, const char *v1)
{
	selinux_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_auth_module);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "selinuxAuthDefaultDomain = %s for %s",
		     v1, sconf->dirname);
	sconf->default_domain = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_default_range(cmd_parms *cmd,
				     void *mconfig, const char *v1)
{
	selinux_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_auth_module);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "selinuxAuthDefaultRange = %s for %s",
		     v1, sconf->dirname);
	sconf->default_range = apr_pstrdup(cmd->pool, v1);

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
		      set_config_file, NULL, OR_OPTIONS,
		      "Apache/SELinux support with HTTP authentication"),
	AP_INIT_TAKE1("selinuxAuthDefaultDomain",
		      set_default_domain, NULL, OR_OPTIONS,
		      "Default domain of Apache/SELinux support"),
	AP_INIT_TAKE1("selinuxAuthDefaultRange",
		      set_default_range, NULL, OR_OPTIONS,
		      "Default range of Apache/SELinux support"),
	{NULL},
};

module AP_MODULE_DECLARE_DATA selinux_auth_module =
{
	STANDARD20_MODULE_STUFF,
	selinux_auth_create_dir_config,	/* create per-directory config */
	NULL,				/* merge per-directory config */
	NULL,				/* server config creator */
	NULL,				/* server config merger */
	selinux_auth_cmds,		/* command table */
	selinux_auth_register_hooks,	/* set up other hooks */
};
