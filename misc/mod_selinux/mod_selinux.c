#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_strings.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <selinux/selinux.h>
#include <selinux/flask.h>

module AP_MODULE_DECLARE_DATA selinux_module;

typedef struct selinux_user_entry
{
	struct selinux_user_entry *next;
	char *username;		/* == NULL means default */
	char *domain;
	char *range;
} selinux_user_entry;

typedef struct selinux_cfg
{
	char *dirname;
	selinux_user_entry *users_list;
} selinux_cfg;

#define username_is_matched(x,y)						\
	(((x)==NULL && (y)==NULL) || ((x)!=NULL && (y)!=NULL && !strcmp((x),(y))))

#define selinux_logger(srv, fmt, ...)					\
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, (srv),	\
				 "%s: " fmt, __FUNCTION__, __VA_ARGS__)

static int selinux_setexeccon(request_rec *r)
{
	selinux_cfg *scfg = ap_get_module_config(r->per_dir_config,
											 &selinux_module);
	selinux_user_entry *s, *matched = NULL;
	security_context_t scon, tcon, newcon;
	char *user, *role, *domain, *range;
	char buffer[512];
	int rc;

	if (!scfg || !r->user)
		goto skip;
	for (s = scfg->users_list; s; s = s->next)
	{
		if (!s->username)
		{
			matched = s;
			continue;
		}
		if (!strcmp(s->username, r->user))
		{
			matched = s;
			break;
		}
	}

skip:
	if (!matched)
	{
		rc = setexeccon(NULL);
		selinux_logger(r->server,
					   "no entry (scfg:%s, user:%s), setexeccon() = %d",
					   scfg ? scfg->dirname : "(null)", r->user, rc);
		return (rc == 0 ? OK : HTTP_INTERNAL_SERVER_ERROR);
	}

	if (getcon_raw(&scon) < 0)
		goto err0;
	if (getfilecon_raw(r->canonical_filename, &tcon) < 0)
		goto err1;
	if (security_compute_create_raw(scon, tcon, SECCLASS_PROCESS, &newcon) < 0)
		goto err2;

	user = strtok(newcon, ":");
	role = strtok(NULL, ":");
	domain = strtok(NULL, ":");
	range = strtok(NULL, "\0");

	snprintf(buffer, sizeof(buffer), "%s:%s:%s:%s", user, role,
			 matched->domain ? matched->domain : domain,
			 matched->range ? matched->range : range);
	rc = setexeccon(buffer);

	selinux_logger(r->server,
				   "(scfg:%s, user:%s, file:%s, scon:%s, tcon:%s)"
				   " setexeccon(%s) = %d",
				   scfg->dirname, r->user, r->canonical_filename,
				   scon, tcon, buffer, rc);

	freecon(scon);
	freecon(tcon);
	freecon(newcon);

	return (rc == 0 ? OK : HTTP_INTERNAL_SERVER_ERROR);

err2:
	freecon(tcon);
err1:
	freecon(scon);
err0:
	return HTTP_INTERNAL_SERVER_ERROR;
}

void *selinux_create_dir_config(apr_pool_t *p, char *dir)
{
	selinux_cfg *scfg = apr_palloc(p, sizeof(selinux_cfg));

	selinux_logger(NULL, "(scfg: %s)", dir);

	scfg->dirname = apr_pstrdup(p, dir);
	scfg->users_list = NULL;

	return scfg;
}

void *selinux_merge_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
	selinux_cfg *base_cfg = base_conf;
	selinux_cfg *new_cfg = new_conf;
	selinux_cfg *scfg;
	selinux_user_entry *s, *t;

	selinux_logger(NULL, "(base:%s, new:%s)",
				   base_cfg->dirname, new_cfg->dirname);

	scfg = apr_palloc(p, sizeof(selinux_cfg));
	scfg->users_list = NULL;
	scfg->dirname = apr_pstrdup(p, new_cfg->dirname);

	/* copy base_cfg */
	for (s = base_cfg->users_list; s; s = s->next)
	{
		t = apr_palloc(p, sizeof(selinux_user_entry));
		t->username = (s->username ? apr_pstrdup(p, s->username) : NULL);
		t->domain   = (s->domain   ? apr_pstrdup(p, s->domain)   : NULL);
		t->range    = (s->range    ? apr_pstrdup(p, s->range)    : NULL);
		t->next     = scfg->users_list;
		scfg->users_list = t;
	}

	/* merge new_cfg */
	for (s = new_cfg->users_list; s; s = s->next)
	{
		for (t = scfg->users_list; t; t = t->next)
		{
			if (username_is_matched(s->username, t->username))
			{
				if (s->domain)
					t->domain = apr_pstrdup(p, s->domain);
				if (s->range)
					t->range = apr_pstrdup(p, s->range);
				break;
			}
		}
		if (t == NULL)
		{
			t = apr_palloc(p, sizeof(selinux_user_entry));
			t->username = (s->username ? apr_pstrdup(p, s->username) : NULL);
			t->domain   = (s->domain   ? apr_pstrdup(p, s->domain)   : NULL);
			t->range    = (s->range    ? apr_pstrdup(p, s->range)    : NULL);
			t->next     = scfg->users_list;
			scfg->users_list = t;
		}
	}

	return scfg;
}

static const char *
selinux_config_user_domain(cmd_parms *cmd, void *mconfig,
						   const char *v1, const char *v2)
{
	selinux_cfg *scfg = ap_get_module_config(cmd->context,
											 &selinux_module);
	selinux_user_entry *s;
	const char *username
		= (!strcmp("__default__", v1) ? NULL : v1);

	selinux_logger(cmd->server, "(user:%s domain:%s scfg:%s)",
				   v1, v2, scfg->dirname);

	/* duplication check */
	for (s = scfg->users_list; s; s = s->next)
	{
		if (username_is_matched(s->username, username))
		{
			if (s->domain)
				return "duplicate selinuxUserDomain entries";
			s->domain = apr_pstrdup(cmd->pool, v2);
			return NULL;
		}
	}
	/* not found */
	s = apr_palloc(cmd->pool, sizeof(selinux_user_entry));
	s->username = username ? apr_pstrdup(cmd->pool, username) : NULL;
	s->domain = apr_pstrdup(cmd->pool, v2);
	s->range = NULL;

	s->next = scfg->users_list;
	scfg->users_list = s;

	return NULL;
}

static const char *
selinux_config_user_range(cmd_parms *cmd, void *mconfig,
						  const char *v1, const char *v2)
{
	selinux_cfg *scfg = ap_get_module_config(cmd->context,
											 &selinux_module);
	selinux_user_entry *s;
	const char *username
		= (!strcmp("__default__", v1) ? NULL : v1);

	selinux_logger(cmd->server, "(user:%s range:%s scfg:%s)",
				   v1, v2, scfg->dirname);

	/* duplication check */
	for (s = scfg->users_list; s; s = s->next)
	{
		if (username_is_matched(s->username, username))
		{
			if (s->range)
				return "duplicate selinuxUserRange entries";
			s->range = apr_pstrdup(cmd->pool, v2);
			return NULL;
		}
	}
	/* not found */
	s = apr_palloc(cmd->pool, sizeof(selinux_user_entry));
	s->username = username ? apr_pstrdup(cmd->pool, username) : NULL;
	s->domain = NULL;
	s->range = apr_pstrdup(cmd->pool, v2);

	s->next = scfg->users_list;
	scfg->users_list = s;

	return NULL;
}

static void selinux_register_hooks(apr_pool_t *p)
{
	ap_hook_fixups(selinux_setexeccon, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec selinux_cmds[] =
{
	AP_INIT_TAKE2("selinuxUserDomain",
				  selinux_config_user_domain,
				  NULL, OR_OPTIONS,
				  "set per user domain of CGI script"),
	AP_INIT_TAKE2("selinuxUserRange",
				  selinux_config_user_range,
				  NULL, OR_OPTIONS,
				  "set per user range of CGI script"),
	{NULL},
};

module AP_MODULE_DECLARE_DATA selinux_module =
{
	STANDARD20_MODULE_STUFF,
	selinux_create_dir_config,
	selinux_merge_dir_config,
	NULL,
	NULL,
	selinux_cmds,
	selinux_register_hooks,
};
