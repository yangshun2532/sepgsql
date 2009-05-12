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

#include <libpq-fe.h>

typedef struct
{
    char *dirname;
    char *host;
    char *port;
    char *options;
    char *database;
    char *dbuser;
    char *dbpassword;
    char *check_password_query;
    char *get_realm_hash_query;
    char *result_field;
    char *domain_field;
} authn_sepgsql_config;

module AP_MODULE_DECLARE_DATA authn_sepgsql_module;

static authn_status
sepgsql_check_password(request_rec *r, const char *user, const char *password)
{
    authn_sepgsql_config   *sconf;
    const char     *params[2];	/* 0: user 1: password */
    PGconn         *conn;
    PGresult       *res;
    char           *value;
    int             fnum = 0;
    authn_status    status;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &authn_sepgsql_module);

    if (!sconf->check_password_query) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "AuthSepgsqlCheckPasswordQuery is not defined");
        return AUTH_GENERAL_ERROR;
    }

    /*
     * (1) open connection
     */
    conn = PQsetdbLogin(sconf->host,
                        sconf->port,
                        sconf->options,
                        NULL,
                        sconf->database,
                        sconf->dbuser,
                        sconf->dbpassword);
    if (!conn) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to connect database server "
                      "(host=%s port=%s options=%s database=%s user=%s pass=%s)",
                      sconf->host, sconf->port, sconf->options,
                      sconf->database, sconf->dbuser, sconf->dbpassword);
        return AUTH_GENERAL_ERROR;
    }

    /*
     * (2) Exec query
     */
    params[0] = user;
    params[1] = password;
    res = PQexecParams(conn,
                       sconf->check_password_query,
                       2,
                       NULL,
                       params,
                       NULL,
                       NULL,
                       0);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Query error: %s for %s (user=%s password=%s)",
                      !res ? "PQexecParams() returns NULL"
                           : PQresultErrorMessage(res),
                      sconf->check_password_query, user, password);
        if (res)
            PQclear(res);
        PQfinish(conn);
        return AUTH_GENERAL_ERROR;
    }

    /*
     * (3) Fetch result
     */
    if (PQntuples(res) == 0) {
        PQclear(res);
        PQfinish(conn);
        return AUTH_USER_NOT_FOUND;
    } else if (PQntuples(res) > 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "Query info: more than one tuples are fetched "
                      "for %s (user=%s password=%s), the header one "
                      "is used to authentication",
                      sconf->check_password_query, user, password);
    }

    if (sconf->result_field) {
        fnum = PQfnumber(res, sconf->result_field);
        if (fnum < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Query error: \"%s\" not found in the result "
                          "for %s (user=%s password=%s)",
                          sconf->result_field,
                          sconf->check_password_query, user, password);
            PQclear(res);
            PQfinish(conn);
            return AUTH_GENERAL_ERROR;
        }
    }

    value = PQgetvalue(res, 0, fnum);
    if (value && strcasecmp(value, "t") == 0)
        status = AUTH_GRANTED;
    else
        status = AUTH_DENIED;

    PQclear(res);
    PQfinish(conn);
    return status;
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
    sconf->domain_field = NULL;

    return sconf;
}

static const char *
set_sepgsql_host(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->host = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_sepgsql_port(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->port = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_sepgsql_options(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->options = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_sepgsql_database(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->database = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_sepgsql_user(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->dbuser = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_sepgsql_password(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->dbpassword = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_sepgsql_check_password_query(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;
    char *query, *pos;
    int i;

    /*
     * ${user} is replaced to $1
     * ${password} is replaced to $2
     */
    query = apr_palloc(cmd->pool, strlen(v1) + 1);
    for (i = 0, pos = query; v1[i] != '\0'; i++) {
        *pos++ = v1[i];
        if (v1[i] == '$' && v1[i+1] == '{') {
            if (strncmp(v1, "${user}", 7) == 0) {
                *pos++ = '1';	/* $1 means user */
                i += 5;
            } else if (strncmp(v1, "${password}", 11) == 0) {
                *pos++ = '2';	/* $2 means password */
                i += 9;
            }
        }
    }
    *pos = '\0';

    sconf->check_password_query = query;

    return NULL;
}

static const char *
set_sepgsql_get_realm_hash_query(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;
    char *query, *pos;
    int i;

    /*
     * ${user} is replaced to $1
     * ${realm} is replaced to $2
     */
    query = apr_palloc(cmd->pool, strlen(v1) + 1);
    for (i=0, pos = query; v1[i] != '\0'; i++) {
        *pos++ = v1[i];
        if (v1[i] == '$' && v1[i+1] == '{') {
            if (strncmp(v1, "${user}", 7) == 0) {
                *pos++ = '1';
                i += 5;
            } else if (strncmp(v1, "${realm}", 8) == 0) {
                *pos++ = '2';
                i += 6;
            }
        }
    }
    *pos = '\0';

    sconf->get_realm_hash_query = query;

    return NULL;
}

static const char *
set_sepgsql_result_field(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->result_field = apr_pstrdup(cmd->pool, v1);

    return NULL;
}

static const char *
set_sepgsql_domain_field(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->domain_field = apr_pstrdup(cmd->pool, v1);

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
  AP_INIT_TAKE1("AuthSepgsqlQuery",
                set_sepgsql_check_password_query, NULL, OR_OPTIONS,
                "Alias of AuthSepgsqlCheckPasswordQuery"),
  AP_INIT_TAKE1("AuthSepgsqlCheckPasswordQuery",
                set_sepgsql_check_password_query, NULL, OR_OPTIONS,
                "Query string to check password"),
  AP_INIT_TAKE1("AuthSepgsqlGetRealmHashQuery",
                set_sepgsql_get_realm_hash_query, NULL, OR_OPTIONS,
                "Query string to get realm hash value"),
  AP_INIT_TAKE1("AuthSepgsqlResultField",
                set_sepgsql_result_field, NULL, OR_OPTIONS,
                "Field name of authentication result"),
  AP_INIT_TAKE1("AuthSepgsqlDomainField",
                set_sepgsql_domain_field, NULL, OR_OPTIONS,
                "Field name of domain/raige pair"),
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
