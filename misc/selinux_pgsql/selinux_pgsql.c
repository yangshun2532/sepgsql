/*
 * mod_selinux_pgsql
 *
 * Apache/SELinux support module with PostgreSQL database.
 * It enables to assign individual security context per user
 * based on the result of SQL query.
 *
 * Copyright (c) 2008 NEC Corporation
 *                    KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 */
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr_strings.h>
#include <ctype.h>

#define MAX_QUERY_PARAMS	32
typedef struct selinux_pgsql_config
{
	char *dirname;

	char *hostname;
	char *port;
	char *database;
	char *username;
	char *password;
	char *connect_timeout;

	char *query;
	char *params[MAX_QUERY_PARAMS];
} selinux_pgsql_config;

/*
 * Forward declaration
 */
module selinux_pgsql_module;

static void *selinux_pgsql_create_dir_config(apr_pool_t *p,
					     char *dirname)
{
	selinux_pgsql_config *sconf
		= apr_pcalloc(p, sizeof(selinux_pgsql_config));

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		     "SELinux: create dir config at %s", dirname);

	sconf->dirname = apr_pstrdup(p, dirname);

	return sconf;
}

static const char *set_pgsql_hostname(cmd_parms *cmd,
				      void *mconfig,
				      const char *v1)
{
	selinux_pgsql_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_pgsql_module);
	sconf->hostname = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_pgsql_port(cmd_parms *cmd,
				  void *mconfig,
				  const char *v1)
{
	selinux_pgsql_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_pgsql_module);
	sconf->port = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_pgsql_database(cmd_parms *cmd,
				      void *mconfig,
				      const char *v1)
{
	selinux_pgsql_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_pgsql_module);
	sconf->database = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_pgsql_username(cmd_parms *cmd,
				      void *mconfig,
				      const char *v1)
{
	selinux_pgsql_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_pgsql_module);
	sconf->username = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_pgsql_password(cmd_parms *cmd,
				      void *mconfig,
				      const char *v1)
{
	selinux_pgsql_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_pgsql_module);
	sconf->password = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_pgsql_connect_timeout(cmd_parms *cmd,
					     void *mconfig,
					     const char *v1)
{
	selinux_pgsql_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_pgsql_module);
	sconf->connect_timeout = apr_pstrdup(cmd->pool, v1);

	return NULL;
}

static const char *set_pgsql_query(cmd_parms *cmd,
				   void *mconfig,
				   const char *v1)
{
	selinux_pgsql_config *sconf
		= ap_get_module_config(cmd->context,
				       &selinux_pgsql_module);
	char *query = apr_pstrdup(cmd->pool, v1);
	char *head, *tail, *ptr;
	int index, shift;

	while (1)
	{
		head = strstr(query, "$(");
		if (!head)
			break;
		tail = strstr(head, ")");
		if (!tail)
			return __FILE__ " : SQL Syntax Error";

		/* sanity checks */
		for (ptr = head + 2; ptr < tail; ptr++)
		{
			int c = *ptr;

			if (!isalnum(c) && c != '_' && c != '%'
			    && c != '.' && c != '@' && c != ':')
				return __FILE__ " : SQL Syntax Error";
		}

		ptr = apr_pstrmemdup(cmd->pool, head + 2, tail - head - 2);
		for (index = 0; index < MAX_QUERY_PARAMS; index++)
		{
			if (!sconf->params[index])
				sconf->params[index] = ptr;

			if (!strcmp(sconf->params[index], ptr))
				break;
		}

		if (index == MAX_QUERY_PARAMS)
			return "Query parameter too much";

		shift = sprintf(head, "$%d", index + 1);
		memmove(head + shift, tail + 1, strlen(tail));
	}
	sconf->query = query;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "Given query: %s", v1);
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "Modified query: %s", sconf->query);
	for (index = 0; index < MAX_QUERY_PARAMS; index++)
	{
		if (!sconf->params[index])
			break;
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
			     "Query param[%d]: %s", index + 1, sconf->params[index]);
	}

	fprintf(stderr, "Given query: %s\n", v1);
	fprintf(stderr, "Modified query: %s\n", sconf->query);
	for (index = 0; index < MAX_QUERY_PARAMS; index++)
        {
                if (!sconf->params[index])
                        break;
		fprintf(stderr, "Query param[%d]: %s\n",
			index + 1, sconf->params[index]);
	}

	return NULL;
}

static void selinux_pgsql_register_hooks(apr_pool_t *p)
{


	return;
}

static const command_rec selinux_pgsql_cmds[] = {
	AP_INIT_TAKE1("selinuxPgsqlHostname",
		      set_pgsql_hostname, NULL, OR_OPTIONS,
		      "PostgreSQL hostname used by " __FILE__),
	AP_INIT_TAKE1("selinuxPgsqlPort",
		      set_pgsql_port, NULL, OR_OPTIONS,
		      "PostgreSQL port number used by " __FILE__),
	AP_INIT_TAKE1("selinuxPgsqlDatabase",
		      set_pgsql_database, NULL, OR_OPTIONS,
		      "PostgreSQL database used by " __FILE__),
	AP_INIT_TAKE1("selinuxPgsqlUsername",
		      set_pgsql_username, NULL, OR_OPTIONS,
		      "PostgreSQL username used by " __FILE__),
	AP_INIT_TAKE1("selinuxPgsqlPassword",
		      set_pgsql_password, NULL, OR_OPTIONS,
		      "PostgreSQL password used by " __FILE__),
	AP_INIT_TAKE1("selinuxPgsqlConnectTimeout",
		      set_pgsql_connect_timeout, NULL, OR_OPTIONS,
		      "PostgreSQL connection timeout used by " __FILE__),
	AP_INIT_TAKE1("selinuxPgsqlQuery",
		      set_pgsql_query, NULL, OR_OPTIONS,
		      "Query to pull domain/range"),
	{NULL},
};

module AP_MODULE_DECLARE_DATA selinux_pgsql_module =
{
	STANDARD20_MODULE_STUFF,
	selinux_pgsql_create_dir_config,	/* create_dir_config */
	NULL,					/* merge_dir_config */
	NULL,					/* create_server_config */
	NULL,					/* merge_server_config */
	selinux_pgsql_cmds,
	selinux_pgsql_register_hooks,
};
