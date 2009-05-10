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

#include "ap_provider.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"

#include "mod_auth.h"

typedef struct
{
  char *dirname;
  char *host;
  char *port;
  char *options;
  char *database;
  char *dbuser;
  char *dbpassword;
  char *result_field;
  char *context_field;
} authn_sepgsql_config;

module AP_MODULE_DECLARE_DATA authn_sepgsql_module;

static authn_status
sepgsql_check_password(request_rec *r, const char *user, const char *password)
{
    return AUTH_GRANTED;
}

static authn_status
sepgsql_get_realm_hash(request_rec *r, const char *user,
		       const char *realm, char **rethash)
{
    return AUTH_GRANTED;
}

/*
 * SE-PostgreSQL authentication API routines
 */
static const authn_provider authn_sepgsql_provider = {
    sepgsql_check_password,
    sepgsql_get_realm_hash,
};

static void authn_sepgsql_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "sepgsql", "0",
                         &authn_sepgsql_provider);
}

static void *authn_sepgsql_create_dir(apr_pool_t *p, char *dirname)
{
    authn_sepgsql_config *sconf
	=  apr_pcalloc(p, sizeof(authn_sepgsql_config));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
		 "authn_sepgsql: create dir config at %s", dirname);

    sconf->dirname = apr_pstrdup(p, dirname);
    sconf->host = NULL;
    sconf->port = NULL;
    sconf->options = NULL;
    sconf->database = NULL;
    sconf->dbuser = NULL;
    sconf->dbpassword = NULL;
    sconf->result_field = NULL;
    sconf->context_field = NULL;

    return sconf;
}

static const char *
set_sepgsql_host(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_port(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_options(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_database(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_user(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_password(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_basic_query(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_digest_query(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_result_field(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const char *
set_sepgsql_context_field(cmd_parms *cmd, void *mconfig, const char *v1)
{
    return NULL;
}

static const command_rec authn_sepgsql_cmds[] = {
  AP_INIT_TAKE1("AuthSepgsqlHost",
		set_sepgsql_host, NULL, OR_OPTIONS,
		"SE-PostgreSQL server host"),
  AP_INIT_TAKE1("AuthSepgsqlPort",
		set_sepgsql_port, NULL, OR_OPTIONS,
		"SE-PostgreSQL server port"),
  AP_INIT_TAKE1("AuthSepgsqlOptions",
		set_sepgsql_options, NULL, OR_OPTIONS,
		"SE-PostgreSQL connection option"),
  AP_INIT_TAKE1("AuthSepgsqlDatabase",
		set_sepgsql_database, NULL, OR_OPTIONS,
		"SE-PostgreSQL database name"),
  AP_INIT_TAKE1("AuthSepgsqlUser",
		set_sepgsql_user, NULL, OR_OPTIONS,
		"SE-PostgreSQL database user"),
  AP_INIT_TAKE1("AuthSepgsqlPassword",
		set_sepgsql_password, NULL, OR_OPTIONS,
		"SE-PostgreSQL database password"),
  AP_INIT_TAKE1("AuthSepgsqlBasicQuery",
		set_sepgsql_basic_query, NULL, OR_OPTIONS,
		"Query string for basic authentication"),
  AP_INIT_TAKE1("AuthSepgsqlDigestQuery",
		set_sepgsql_digest_query, NULL, OR_OPTIONS,
		"Query string for basic authentication"),
  AP_INIT_TAKE1("AuthSepgsqlResultField",
		set_sepgsql_result_field, NULL, OR_OPTIONS,
		"Field name of authentication result"),
  AP_INIT_TAKE1("AuthSepgsqlContextField",
		set_sepgsql_context_field, NULL, OR_OPTIONS,
		"Field name of security context"),
  {NULL}
};

module AP_MODULE_DECLARE_DATA authn_sepgsql_module = {
  STANDARD20_MODULE_STUFF,
  authn_sepgsql_create_dir,     /* dir config creater */
  NULL,                         /* dir merger --- default is to override */
  NULL,                         /* server config */
  NULL,                         /* merge server config */
  authn_sepgsql_cmds,           /* command apr_table_t */
  authn_sepgsql_hooks,          /* register hooks */
};
