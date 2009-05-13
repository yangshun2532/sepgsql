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

typedef struct authn_sepgsql_setenv authn_sepgsql_setenv;
struct authn_sepgsql_setenv {
    authn_sepgsql_setenv *next;
    char *field_name;
    char *setenv_name;
};

typedef struct authn_sepgsql_config authn_sepgsql_config;
struct authn_sepgsql_config
{
    char *dirname;
    char *host;
    char *port;
    char *options;
    char *database;
    char *dbuser;
    char *dbpass;
    char *check_query;
    char *check_field;
    int   check_user_pnum;
    int   check_pass_pnum;
    char *hash_query;
	int   hash_user_pnum;
	int   hash_realm_pnum;
	char *hash_field;
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

static authn_status
sepgsql_check_password(request_rec *r, const char *user, const char *password)
{
    authn_sepgsql_config   *sconf;
    const char     *params[2];
    int             nparams;
    PGconn         *conn;
    PGresult       *res;
    char           *value;
    char            debug_qry[MAX_STRING_LEN];
    int             i, ofs, fnum = 0;
    authn_status    status;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &authn_sepgsql_module);

    if (!sconf->check_query) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "AuthSepgsqlCheckQuery is not defined");
        return AUTH_GENERAL_ERROR;
    }

    /*
     * Set up query parameters
     */
    nparams = 0;
    if (sconf->check_user_pnum > 0) {
        params[sconf->check_user_pnum - 1] = user;
        nparams++;
    }
    if (sconf->check_pass_pnum > 0) {
        params[sconf->check_pass_pnum - 1] = password;
        nparams++;
    }

    /*
     * Debug message
     */
    ofs = snprintf(debug_qry, sizeof(debug_qry), "\"%s\"", sconf->check_query);
    if (nparams > 0) {
        ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs, " Params (");
        for (i=0; i < nparams; i++) {
            ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs,
                            "%s$%d = \"%s\" (%s)",
                            (i > 0 ? " ," : ""), i+1, params[i],
                            (params[i] == user ? "user" : "password"));
        }
        ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs, ")");
    }

    /*
     * Open database connection
     */
    conn = PQsetdbLogin(sconf->host,
                        sconf->port,
                        sconf->options,
                        NULL,
                        sconf->database,
                        sconf->dbuser,
                        sconf->dbpass);
    if (!conn) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to connect database server "
                      "(host=%s port=%s options=%s database=%s dbuser=%s dbpass=%s)",
                      sconf->host, sconf->port, sconf->options,
                      sconf->database, sconf->dbuser, sconf->dbpass);
        return AUTH_GENERAL_ERROR;
    }

    /*
     * Exec query
     */
    res = PQexecParams(conn, sconf->check_query, nparams,
                       NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "PQexecParams: %s: %s",
                      !res ? "fatal error"
                           : PQresultErrorMessage(res),
                      debug_qry);
        if (res)
            PQclear(res);
        PQfinish(conn);
        return AUTH_GENERAL_ERROR;
    }

    /*
     * Fetch result
     */
    if (PQntuples(res) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "No matched tuples: %s", debug_qry);
        status = AUTH_USER_NOT_FOUND;
        goto out;
    }

    if (PQntuples(res) > 1) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "More than one tuples matched: %s, "
                      "the first one is used for authentication",
                      debug_qry);
    }

    if (sconf->check_field) {
        fnum = PQfnumber(res, sconf->check_field);
        if (fnum < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Field \"%s\" not found: %s",
                          sconf->check_field, debug_qry);
            status = AUTH_GENERAL_ERROR;
            goto out;
        }
    }

    value = PQgetvalue(res, 0, fnum);
    if (!value) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "PQgetvalue() returned invalid value: %s", debug_qry);
        status = AUTH_GENERAL_ERROR;
        goto out;
    }

    if (strcasecmp(value, "t") != 0)
        status = AUTH_DENIED;
    else {
        status = AUTH_GRANTED;
        sepgsql_setenv(r, sconf, res);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "CheckQuery: %s Result: %s", debug_qry,
                  (status == AUTH_GRANTED ? "GRANTED" : "DENIED"));

out:
    PQclear(res);
    PQfinish(conn);

    return status;
}

static authn_status
sepgsql_get_realm_hash(request_rec *r, const char *user,
                       const char *realm, char **rethash)
{
    authn_sepgsql_config   *sconf;
    const char     *params[2];
    int             nparams;
    PGconn         *conn;
    PGresult       *res;
    char           *value;
    char            debug_qry[MAX_STRING_LEN];
    int             i, ofs, fnum = 0;
    authn_status    status;

    sconf = ap_get_module_config(r->per_dir_config,
                                 &authn_sepgsql_module);

    if (!sconf->hash_query) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "AuthSepgsqlHashQuery is not defined");
        return AUTH_GENERAL_ERROR;
    }

    /*
     * Set up query parameters
     */
    nparams = 0;
    if (sconf->check_user_pnum > 0) {
        params[sconf->hash_user_pnum - 1] = user;
        nparams++;
    }
    if (sconf->check_pass_pnum > 0) {
        params[sconf->hash_realm_pnum - 1] = realm;
        nparams++;
    }

    /*
     * Debug message
     */
    ofs = snprintf(debug_qry, sizeof(debug_qry), "\"%s\"", sconf->hash_query);
    if (nparams > 0) {
        ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs, " Params (");
        for (i=0; i < nparams; i++) {
            ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs,
                            "%s$%d = \"%s\" (%s)",
                            (i > 0 ? " ," : ""), i+1, params[i],
                            (params[i] == user ? "user" : "realm"));
        }
        ofs += snprintf(debug_qry + ofs, sizeof(debug_qry) - ofs, ")");
    }

    /*
     * Open database connection
     */
    conn = PQsetdbLogin(sconf->host,
                        sconf->port,
                        sconf->options,
                        NULL,
                        sconf->database,
                        sconf->dbuser,
                        sconf->dbpass);
    if (!conn) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to connect database server "
                      "(host=%s port=%s options=%s database=%s dbuser=%s dbpass=%s)",
                      sconf->host, sconf->port, sconf->options,
                      sconf->database, sconf->dbuser, sconf->dbpass);
        return AUTH_GENERAL_ERROR;
    }

    /*
     * Exec query
     */
    res = PQexecParams(conn, sconf->hash_query, nparams,
                       NULL, params, NULL, NULL, 0);

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "PQexecParams: %s: %s",
                      !res ? "fatal error"
                           : PQresultErrorMessage(res),
                      debug_qry);
        if (res)
            PQclear(res);
        PQfinish(conn);
        return AUTH_GENERAL_ERROR;
    }

    /*
     * Fetch result
     */
    if (PQntuples(res) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "No matched tuples: %s", debug_qry);
        status = AUTH_USER_NOT_FOUND;
        goto out;
    }

    if (PQntuples(res) > 1) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                      "More than one tuples matched: %s, "
                      "the first one is used for authentication",
                      debug_qry);
    }

    if (sconf->check_field) {
        fnum = PQfnumber(res, sconf->hash_field);
        if (fnum < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Field \"%s\" not found: %s",
                          sconf->hash_field, debug_qry);
            status = AUTH_GENERAL_ERROR;
            goto out;
        }
    }

    value = PQgetvalue(res, 0, fnum);
    if (!value) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "PQgetvalue() returned invalid value: %s", debug_qry);
        status = AUTH_GENERAL_ERROR;
        goto out;
    }

    *rethash = apr_pstrdup(r->pool, value);
    status = AUTH_USER_FOUND;
    sepgsql_setenv(r, sconf, res);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "HashQuery: %s Hash: %s", debug_qry, value);

out:
    PQclear(res);
    PQfinish(conn);

    return status;
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
    sconf->dbpass = NULL;
    sconf->check_query = NULL;
    sconf->check_field = NULL;
    sconf->hash_query = NULL;
    sconf->hash_field = NULL;
    sconf->setenv_list = NULL;

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
set_sepgsql_options(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->options = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlOptions = %s at %s",
                 sconf->options, sconf->dirname);
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
set_sepgsql_dbuser(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->dbuser = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlDbUser = %s at %s",
                 sconf->dbuser, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_dbpass(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->dbpass = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlDbPass = %s at %s",
                 sconf->dbpass, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_check_query(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;
    char *query, *pos;
    int i;

    sconf->check_user_pnum = 0;
    sconf->check_pass_pnum = 0;

    query = apr_palloc(cmd->pool, strlen(v1) + 1);
    for (i = 0, pos = query; v1[i] != '\0'; i++) {
        *pos++ = v1[i];
        if (v1[i] == '$') {
            if (strncasecmp(v1+i, "$(user)", 7) == 0) {
                if (sconf->check_user_pnum == 0)
                    sconf->check_user_pnum = sconf->check_pass_pnum + 1;

                *pos++ = ('0' + sconf->check_user_pnum);
                i += 6;
            } else if (strncasecmp(v1+i, "$(password)", 11) == 0) {
                if (sconf->check_pass_pnum == 0)
                    sconf->check_pass_pnum = sconf->check_user_pnum +1;

                *pos++ = ('0' + sconf->check_pass_pnum);
                i += 10;
            } else {
                return "Only $(user) and $(password) are supported"
                    " at AuthSepgsqlCheckQuery directive.";
            }
        }
    }
    *pos = '\0';

    sconf->check_query = query;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlCheckQuery = %s at %s",
                 sconf->check_query, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_hash_query(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;
    char *query, *pos;
    int i;

    sconf->hash_user_pnum = 0;
    sconf->hash_realm_pnum = 0;

    query = apr_palloc(cmd->pool, strlen(v1) + 1);
    for (i=0, pos = query; v1[i] != '\0'; i++) {
        *pos++ = v1[i];
        if (v1[i] == '$') {
            if (strncasecmp(v1+i, "$(user)", 7) == 0) {
                if (sconf->hash_user_pnum == 0)
                    sconf->hash_user_pnum = sconf->hash_realm_pnum + 1;

                *pos++ = ('0' + sconf->hash_user_pnum);
                i += 6;
            } else if (strncasecmp(v1+i, "$(realm)", 8) == 0) {
                if (sconf->hash_realm_pnum == 0)
                    sconf->hash_realm_pnum = sconf->hash_user_pnum + 1;

                *pos++ = ('0' + sconf->hash_realm_pnum);
                i += 7;
            } else {
                return "Only $(user) and $(realm) are supported"
                    " at AuthSepgsqlHashQuery directive.";
            }
        }
    }
    *pos = '\0';

    sconf->hash_query = query;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlHashQuery = %s at %s",
                 sconf->hash_query, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_check_field(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->check_field = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlCheckField = %s at %s",
                 sconf->check_field, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_hash_field(cmd_parms *cmd, void *mconfig, const char *v1)
{
    authn_sepgsql_config *sconf = mconfig;

    sconf->hash_field = apr_pstrdup(cmd->pool, v1);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "AuthSepgsqlHashField = %s at %s",
                 sconf->hash_field, sconf->dirname);
    return NULL;
}

static const char *
set_sepgsql_setenv_field(cmd_parms *cmd, void *mconfig,
						 const char *v1, const char *v2)
{
    authn_sepgsql_config *sconf = mconfig;
	authn_sepgsql_setenv *entry, *cur;

	entry = apr_palloc(cmd->pool, sizeof(authn_sepgsql_setenv));
	entry->next = NULL;
	entry->field_name = apr_pstrdup(cmd->pool, v1);
	entry->setenv_name = (!v2 ? entry->field_name
						      : apr_pstrdup(cmd->pool, v2));

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
  AP_INIT_TAKE1("AuthSepgsqlDbUser",
                set_sepgsql_dbuser, NULL, OR_OPTIONS,
                "SE-PostgreSQL database user"),
  AP_INIT_TAKE1("AuthSepgsqlDbPass",
                set_sepgsql_dbpass, NULL, OR_OPTIONS,
                "SE-PostgreSQL database password"),
  AP_INIT_TAKE1("AuthSepgsqlCheckQuery",
                set_sepgsql_check_query, NULL, OR_OPTIONS,
                "Query string to check password"),
  AP_INIT_TAKE1("AuthSepgsqlHashQuery",
                set_sepgsql_hash_query, NULL, OR_OPTIONS,
                "Query string to get realm hash value"),
  AP_INIT_TAKE1("AuthSepgsqlCheckField",
                set_sepgsql_check_field, NULL, OR_OPTIONS,
                "Field name of check query result"),
  AP_INIT_TAKE1("AuthSepgsqlHashField",
                set_sepgsql_hash_field, NULL, OR_OPTIONS,
                "Field name of hash query result"),
  AP_INIT_TAKE12("AuthSepgsqlSetEnvField",
                 set_sepgsql_setenv_field, NULL, OR_OPTIONS,
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
