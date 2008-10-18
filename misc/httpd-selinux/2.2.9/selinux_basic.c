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

typedef struct
{
	char *dirname;
	char *config_file;
	char *default_domain;
} selinux_basic_config;

/*
 * Forward declaration
 */
module AP_MODULE_DECLARE_DATA selinux_basic_module;

#define WHITESPACE	" \t\n\r"

static int selinux_basic_lookup_entry(request_rec *r, const char *filename, char **p_entry)
{
	apr_ipsubnet_t *ipsub;
	char buffer[1024], *ident, *entry, *mask, *tmp;
	FILE *filp;
	int lineno = 1;

	filp = fopen(filename, "rb");
	if (!filp)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "could not open configuration file : %s (%s)",
			     filename, strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	while (fgets(buffer, sizeof(buffer), filp))
	{
		int cond = 0;

		tmp = strchr(buffer, '#');
		if (tmp)
			*tmp = '\0';

		ident = strtok_r(buffer, WHITESPACE, &tmp);
		if (!ident)
			continue;	/* empty row */

		if (*ident == '!')
		{
			ident++;
			cond = 1;
		}

		entry = strtok_r(NULL, WHITESPACE, &tmp);
		if (!entry || strtok_r(NULL, WHITESPACE, &tmp))
		{
			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server,
				     "syntax error at %s:%u", filename, lineno);
			flose(filp);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		mask = strchr(ident, '/');
		if (mask)
			*mask++ = '\0';

		if (apr_ipsubnet_create(&ipsub, ident, mask, r->pool) == APR_SUCCESS)
		{
			if (apr_ipsubnet_test(ipsub, r->connection->remote_addr))
			{
				if (!cond)
					goto match;
			}
			else if (cond)
				goto match;
		}
		else if (r->user != NULL)
		{
			if (mask)
				*--mask = '/';	/* fixup identifier */
			if (strcmp(r->user, ident) == 0)
			{
				if (!cond)
					goto match;
			}
			else if (cond)
				goto match;
		}
		lineno++;
	}
	fclose(filp);
	*p_entry = NULL;
	return 0;	/* no matched entry */

match:
	fclose(filp);
	*p_entry = apr_pstrdup(r->pool, entry);
	return 0;
}

static int selinux_basic_set_context(request_rec *r, const char *entry)
{
	security_context_t security_context;
	context_t context;
	char *domain, *range;

	if (!entry)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "no matched entry and default setting");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	domain = apr_pstrdup(r->pool, entry);
	range = strchr(domain, ':');
	if (range)
		*range++ = '\0';

	if (strcmp(domain, "*") == 0)
		domain = NULL;
	if (strcmp(range, "") == 0)
		range = NULL;
	/*
	 * Set a new security context
	 */
	if (getcon_raw(&security_context) < 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: getcon_raw() failed (%s)",
			     strerror(errno));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	context = context_new(security_context);
	if (!context)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: context_new(%s) failed (%s)",
			     security_context, strerror(errno));
		freecon(security_context);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	freecon(security_context);

	if (domain)
		context_type_set(context, domain);
	if (range)
		context_range_set(context, range);

	security_context = context_str(context);
	if (!security_context)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: context_str() failed (%s)",
			     strerror(errno));
		context_free(context);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (setcon(security_context) < 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "SELinux: setcon(%s) for %s failed (%s)",
			     security_context,
			     r->user ? r->user : "anonymous",
			     strerror(errno));
		context_free(context);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
		     "SELinux: setcon(%s) for %s",
		     security_context,
		     r->user ? r->user : "anonymous");
	context_free(context);

	return 0;
}

static int selinux_basic_handler(request_rec *r)
{
	selinux_basic_config *sconf;
	char *entry = NULL;
	int rc;

	sconf = ap_get_module_config(r->per_dir_config,
				     &selinux_basic_module);
	if (!sconf)
		return DECLINED;	/* do nothing */

	if (sconf->config_file)
	{
		rc = selinux_basic_lookup_entry(r, sconf->config_file, &entry);
		if (rc)
			return rc;
	}
	else if (!sconf->default_domain)
		return DECLINED;	/* do nothing */

	if (!entry && sconf->default_domain)
		entry = apr_pstrdup(r->pool, sconf->default_domain);

	rc = selinux_basic_set_context(r, entry);
	if (rc)
		return rc;

	return DECLINED;
}

static void *selinux_basic_create_dir_config(apr_pool_t *p, char *dirname)
{
	selinux_basic_config *sconf
		= apr_pcalloc(p, sizeof(selinux_basic_config));

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		     "SELinux: create dir config at %s", dirname);

	sconf->dirname = apr_pstrdup(p, dirname);
	sconf->config_file = NULL;
	sconf->default_domain = NULL;

	return sconf;
}

static const char *set_config_file(cmd_parms *cmd,
				   void *mconfig, const char *v1)
{
	selinux_basic_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_basic_module);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "selinuxBasicConfigFile = '%s' for '%s'",
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
	selinux_basic_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_basic_module);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "selinuxBasicDefaultDomain = '%s' for '%s'",
		     v1, sconf->dirname);
	sconf->default_domain = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static void selinux_basic_register_hooks(apr_pool_t *p)
{
	ap_hook_handler(selinux_basic_handler,
			NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static const command_rec selinux_basic_cmds[] = {
	AP_INIT_TAKE1("selinuxBasicConfigFile",
		      set_config_file, NULL, OR_OPTIONS,
		      "Apache/SELinux plus configuration file"),
	AP_INIT_TAKE1("selinuxBasicDefaultDomain",
		      set_default_domain, NULL, OR_OPTIONS,
		      "Default security context of contents handler"),
	{NULL},
};

module AP_MODULE_DECLARE_DATA selinux_basic_module =
{
	STANDARD20_MODULE_STUFF,
	selinux_basic_create_dir_config,	/* create per-directory config */
	NULL,					/* merge per-directory config */
	NULL,					/* server config creator */
	NULL,					/* server config merger */
	selinux_basic_cmds,			/* command table */
	selinux_basic_register_hooks,		/* set up other hooks */
};
