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

#ifndef APACHE_MPM_AUTH_SELINUX_H
#define APACHE_MPM_AUTH_SELINUX_H

extern int auth_selinux_post_config(apr_pool_t *pconf, apr_pool_t *plog,
				    apr_pool_t *ptemp, server_rec *s);
extern int auth_selinux_handler(request_rec *r);

extern void *auth_selinux_create_dir_config(apr_pool_t *p, char *dirname);

extern void *auth_selinux_merge_dir_config(apr_pool_t *p, void *basep, void *newp);

extern const char *
auth_selinux_config_user_domain(cmd_parms *cmd, void *mconfig,
				const char *v1, const char *v2);
extern const char *
auth_selinux_config_user_range(cmd_parms *cmd, void *mconfig,
			       const char *v1, const char *v2);

#define AP_AUTH_SELINUX_COMMAND						\
    AP_INIT_TAKE2("selinuxUserDomain",					\
		  auth_selinux_config_user_domain, NULL, OR_OPTIONS,	\
		  "set per user domain of contains handler"),		\
    AP_INIT_TAKE2("selinuxUserRange",					\
		  auth_selinux_config_user_range, NULL, OR_OPTIONS,	\
		  "set per user range of contains handler")

module AP_MODULE_DECLARE_DATA mpm_selinux_module;

#endif	/* APACHE_MPM_AUTH_SELINUX_H */
