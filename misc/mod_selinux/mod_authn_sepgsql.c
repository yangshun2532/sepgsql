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

#include <ctype.h>
#include <libpq-fe.h>

typedef struct authn_sepgsql_setenv authn_sepgsql_setenv;
struct authn_sepgsql_setenv {
    authn_sepgsql_setenv *next;

    char *field_name;
    char *setenv_name;
};

typedef struct authn_sepgsql_query authn_sepgsql_query;
struct authn_sepgsql_query {
    char     *query_string;
    char     *field_name;

    /* Run-time parameters */
    int       nparams;

    int       user_pnum;          /* $(user) */
    int       password_pnum;      /* $(password) */
    int       realm_pnum;         /* $(realm) */
    int       remote_addr_pnum;   /* $(remote_addr) */
    int       method_pnum;        /* $(method) */
    int       uri_pnum;           /* $(uri) */
};
#define MAX_NPARAMS     6

typedef struct authn_sepgsql_config authn_sepgsql_config;
struct authn_sepgsql_config
{
    char     *dirname;
    /* Database connection parameters */
    char     *conn_info;
    char     *host;
    char     *port;
    char     *database;
    char     *user;
    char     *password;

    /* Basic authentication  */
    authn_sepgsql_query    *check_query;

    /* Digest authentication */
    authn_sepgsql_query    *hash_query;

    /* Extra user information delivers */
    authn_sepgsql_setenv *setenv_list;
};

module AP_MODULE_DECLARE_DATA authn_sepgsql_module;

static void
sepgsql_setenv(request_rec *r, authn_sepgsql_config *sconf, PGresult *res)
{
    authn_sepgsql_setenv *entry;
    const char *value;
    int fnum;

    for (entry = sconf->setenv_list; entry; entry = entry->next) {
        fnum = PQfnumber(res, entry->field_name);
        if (fnum < 0)
            continue;

        value = PQgetvalue(res, 0, fnum);
        if (!value)
            continue;

        apr_table_set(r->subprocess_env, entry->setenv_name, value);
    }
}

static void
sepgsql_setup_params(authn_sepgsql_query *query, const char *pbuffer[],
                     request_rec *r, const char *user,
                     const char *password, const char *realm)
{
    if (query->user_pnum > 0)
        pbuffer[query->user_pnum - 1] = user;
    if (query->password_pnum > 0)
        pbuffer[query->password_pnum - 1] = password;
    if (query->realm_pnum > 0)
        pbuffer[query->realm_pnum - 1] = realm;
    if (query->remote_addr_pnum > 0)
        pbuffer[query->remote_addr_pnum - 1] = r->connection->remote_ip;
    if (query->method_pnum > 0)
        pbuffer[query->method_pnum - 1] = r->method;
    if (query->uri_pnum > 0)
        pbuffer[query->uri_pnum - 1] = r->uri;
}

static char *
sepgsql_run_query(request_rec *r, authn_sepgsql_config *sconf,
                  authn_sepgsql_query *query, const char *pbuffer[],
                  authn_status *error_code)
{
    PGconn     *conn;
    PGresult   *res = NULL;
    char       *result = NULL;
    char       *value;
    char        debug_qry[MAX_STRING_LEN];
    int         i, ofs, fnum = 0;

    /*
     * Setup debug message
     */
    ofs = snprintf(debug_qry, sizeof(debug_qry), "\"%s\"", query->query_string);
    if (query->nparams > 0) {
        ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs, " Params (");
        for (i=0; i < query->nparams; i++) {
            if (i > 0)
                ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs, ", ");
            ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs,
                            "$%u = \"%s\"", i+1, pbuffer[i]);
        }
        ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs, ")");
    }

    /*
     * Open database connection
     */
    if (sconf->conn_info) {
        conn = PQconnectdb(sconf->conn_info);
        if (!conn) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "unable to connect database server (%s)",
                         sconf->conn_info);
            *error_code = AUTH_GENERAL_ERROR;
            goto out;
        }
    } else {
        conn = PQsetdbLogin(sconf->host,
                            sconf->port,
                            NULL,
                            NULL,
                            sconf->database,
                            sconf->user,
                            sconf->password);
        if (!conn) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "unable to connect database server "
                         "(host=%s port=%s dbname=%s user=%s password=%s)",
                         sconf->host, sconf->port, sconf->database,
                         sconf->user, sconf->password);
            *error_code = AUTH_GENERAL_ERROR;
            goto out;
        }
    }

    /*
     * Exec query with runtime patameters
     */
    res = PQexecParams(conn, query->query_string, query->nparams,
                       NULL, pbuffer, NULL, NULL, 0);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "PQexecParams: %s: %s",
                      (!res ? "fatal error" : PQresultErrorMessage(res)),
                      debug_qry);
        *error_code = AUTH_GENERAL_ERROR;
        goto out;
    }

    /*
     * Fetch result
     */
    if (PQntuples(res) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "No matched tuples: %s", debug_qry);
        *error_code = AUTH_USER_NOT_FOUND;
        goto out;
    }

    if (PQntuples(res) > 1) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "The first result is used for authentication "
                      "in the multiple result set of: %s", debug_qry);
    }

    if (query->field_name) {
        fnum = PQfnumber(res, query->field_name);
        if (fnum < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Field \"%s\" not found: %s",
                          query->field_name, debug_qry);
            *error_code = AUTH_GENERAL_ERROR;
            goto out;
        }
    }

    value = PQgetvalue(res, 0, fnum);
    if (!value) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "PQgetvalue() returned invalid value: %s",
                      debug_qry);
        *error_code = AUTH_GENERAL_ERROR;
        goto out;
    }

    result = apr_pstrdup(r->pool, value);

    sepgsql_setenv(r, sconf, res);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "result: %s for %s", result, debug_qry);

out:
    if (res)
        PQclear(res);
    if (conn)
        PQfinish(conn);

    return result;
}

static authn_status
sepgsql_check_password(request_rec *r, const char *user, const char *password)
{
    authn_sepgsql_config   *sconf;
    const char     *pbuffer[MAX_NPARAMS];
    char           *result;
    authn_status    status;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &authn_sepgsql_module);

    if (!sconf->check_query) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "AuthSepgsqlCheckQuery is not defined");
        return AUTH_GENERAL_ERROR;
    }
    sepgsql_setup_params(sconf->check_query, pbuffer,
                         r, user, password, NULL);

    result = sepgsql_run_query(r, sconf, sconf->check_query,
                               pbuffer, &status);
    if (!result)
        return status;

    /*
     * If user/password matched, result is "true"
     */
    if (!strcasecmp(result, "t"))
        return AUTH_GRANTED;

    return AUTH_DENIED;
}

static authn_status
sepgsql_get_realm_hash(request_rec *r, const char *user,
                       const char *realm, char **rethash)
{
    authn_sepgsql_config   *sconf;
    const char     *pbuffer[MAX_NPARAMS];
    char           *result;
    authn_status    status;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &authn_sepgsql_module);

    if (!sconf->hash_query) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "AuthSepgsqlHashQuery is not defined");
        return AUTH_GENERAL_ERROR;
    }
    sepgsql_setup_params(sconf->hash_query, pbuffer,
                         r, user, NULL, realm);

    result = sepgsql_run_query(r, sconf, sconf->hash_query,
                               pbuffer, &status);
    if (!result)
        return status;

    *rethash = result;

    return AUTH_USER_FOUND;
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

    memset(sconf, 0, sizeof(authn_sepgsql_config));
    sconf->dirname = apr_pstrdup(p, dirname);

    return sconf;
}

static const char *
set_sepgsql_host(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->host = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlHost = %s at %s",
                 sconf->host, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_conn_info(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->conn_info = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlConnInfo = %s at %s",
                 sconf->conn_info, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_port(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->port = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlPort = %s at %s",
                 sconf->port, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_database(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->database = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlDatabase = %s at %s",
                 sconf->database, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_user(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->user = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlUser = %s at %s",
                 sconf->user, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_password(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->password = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlPassword = %s at %s",
                 sconf->password, sconf->dirname);
    return NULL;
}

static authn_sepgsql_query *
sepgsql_setup_query(cmd_parms *cmd, const char *fname, const char *qstring)
{
    authn_sepgsql_query *query;
    char   *pos;

    query = apr_palloc(cmd->pool, sizeof(authn_sepgsql_query));
    memset(query, 0, sizeof(authn_sepgsql_query));

    query->query_string = apr_palloc(cmd->pool, strlen(qstring) + 1);
    if (fname)
        query->field_name = apr_pstrdup(cmd->pool, fname);

    for (pos = query->query_string; *qstring != '\0'; qstring++)
    {
        if (*qstring != '$') {
            *pos++ = *qstring;
        }
        else if (!strncasecmp(qstring, "$(user)", 7)) {
            if (query->user_pnum == 0)
                query->user_pnum = ++query->nparams;
            pos += sprintf(pos, "$%u", query->user_pnum);
            qstring += 6;
        }
        else if (!strncasecmp(qstring, "$(password)", 11)) {
            if (query->password_pnum == 0)
                query->password_pnum = ++query->nparams;
            pos += sprintf(pos, "$%u", query->password_pnum);
            qstring += 10;
        }
        else if (!strncasecmp(qstring, "$(realm)", 8)) {
            if (query->realm_pnum == 0)
                query->realm_pnum = ++query->nparams;
            pos += sprintf(pos, "$%u", query->realm_pnum);
            qstring += 7;
        }
        else if (!strncasecmp(qstring, "$(remote_addr)", 14)) {
            if (query->remote_addr_pnum == 0)
                query->remote_addr_pnum = ++query->nparams;
            pos += sprintf(pos, "$%u", query->remote_addr_pnum);
            qstring += 13;
        }
        else if (!strncasecmp(qstring, "$(method)", 9)) {
            if (query->method_pnum == 0)
                query->method_pnum = ++query->nparams;
            pos += sprintf(pos, "$%u", query->method_pnum);
            qstring += 8;
        }
        else if (!strncasecmp(qstring, "$(uri)", 6)) {
            if (query->uri_pnum == 0)
                query->uri_pnum = ++query->nparams;
            pos += sprintf(pos, "$%u", query->uri_pnum);
            qstring += 5;
        }
        else {
            /* unsupported replacement */
            return NULL;
        }
    }

    return query;
}

static const char *
set_sepgsql_check_query(cmd_parms *cmd, void *mconfig,
                        const char *v1, const char *v2)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->check_query = (v2 ? sepgsql_setup_query(cmd, v1, v2)
                             : sepgsql_setup_query(cmd, NULL, v1));
    if (!sconf->check_query)
        return apr_psprintf(cmd->pool, "Invalid query: %s", v2);

    return NULL;
}

static const char *
set_sepgsql_hash_query(cmd_parms *cmd, void *mconfig,
                       const char *v1, const char *v2)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->hash_query = (v2 ? sepgsql_setup_query(cmd, v1, v2)
                            : sepgsql_setup_query(cmd, NULL, v1));
    if (!sconf->hash_query)
        return apr_psprintf(cmd->pool, "Invalid query: %s", v2);

    return NULL;
}

static const char *
set_sepgsql_setenv(cmd_parms *cmd, void *mconfig,
                   const char *v1, const char *v2)
{
    authn_sepgsql_config *sconf = mconfig;
	authn_sepgsql_setenv *entry, *cur;

	entry = apr_palloc(cmd->pool, sizeof(authn_sepgsql_setenv));
	entry->next = NULL;
	entry->field_name = apr_pstrdup(cmd->pool, v1);
    if (v2)
        entry->setenv_name = apr_pstrdup(cmd->pool, v2);
    else {
        char   *pos;
        int     i;

        entry->setenv_name = apr_palloc(cmd->pool, strlen(v1) + 15);

        pos = entry->setenv_name;
        pos += sprintf(pos, "AUTH_SEPGSQL_");
        for (i=0; v1[i] != '\0'; i++)
            *pos++ = toupper(v1[i]);
        *pos = '\0';
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlSetEnvField = %s/%s at %s",
                 entry->field_name, entry->setenv_name, sconf->dirname);

	if (!sconf->setenv_list) {
		sconf->setenv_list = entry;
		return NULL;
	}

	for (cur = sconf->setenv_list; cur->next; cur = cur->next);

	cur->next = entry;

    return NULL;
}

static const command_rec authn_sepgsql_cmds[] = {
    AP_INIT_TAKE1("AuthSepgsqlConnInfo",
                  set_sepgsql_conn_info, NULL, OR_OPTIONS,
                  "SE-PostgreSQL database connection info"),
    AP_INIT_TAKE1("AuthSepgsqlHost",
                  set_sepgsql_host, NULL, OR_OPTIONS,
                  "SE-PostgreSQL server host"),
    AP_INIT_TAKE1("AuthSepgsqlPort",
                  set_sepgsql_port, NULL, OR_OPTIONS,
                  "SE-PostgreSQL server port"),
    AP_INIT_TAKE1("AuthSepgsqlDatabase",
                  set_sepgsql_database, NULL, OR_OPTIONS,
                  "SE-PostgreSQL database name"),
    AP_INIT_TAKE1("AuthSepgsqlUser",
                  set_sepgsql_user, NULL, OR_OPTIONS,
                  "SE-PostgreSQL database user"),
    AP_INIT_TAKE1("AuthSepgsqlPassword",
                  set_sepgsql_password, NULL, OR_OPTIONS,
                  "SE-PostgreSQL database password"),
    AP_INIT_TAKE12("AuthSepgsqlCheckQuery",
                   set_sepgsql_check_query, NULL, OR_OPTIONS,
                   "Query string to check password"),
    AP_INIT_TAKE12("AuthSepgsqlHashQuery",
                   set_sepgsql_hash_query, NULL, OR_OPTIONS,
                   "Query string to get realm hash value"),
    AP_INIT_TAKE12("AuthSepgsqlSetEnv",
                   set_sepgsql_setenv, NULL, OR_OPTIONS,
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
