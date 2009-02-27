/*
 +----------------------------------------------------------------------+
 | PHP Version 5                                                        |
 +----------------------------------------------------------------------+
 | Copyright (c) 1997-2009 The PHP Group                                |
 +----------------------------------------------------------------------+
 | This source file is subject to version 3.01 of the PHP license,      |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.php.net/license/3_01.txt                                  |
 | If you did not receive a copy of the PHP license and are unable to   |
 | obtain it through the world-wide-web, please send a note to          |
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: KaiGai Kohei <kaigai@ak.jp.nec.com>                          |
 +----------------------------------------------------------------------+
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

#if HAVE_SELINUX

#include "php_selinux.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <selinux/selinux.h>

/*
 * SELinux functions
 */
zend_function_entry selinux_functions[] = {
	/* global state API */
	PHP_FE(selinux_is_enabled,		NULL)
	PHP_FE(selinux_mls_is_enabled,		NULL)
	PHP_FE(selinux_getenforce,		NULL)
	PHP_FE(selinux_setenforce,		NULL)
	PHP_FE(selinux_policyvers,		NULL)

	/*  wrappers for the /proc/pid/attr API */
	PHP_FE(selinux_getcon,			NULL)
	PHP_FE(selinux_setcon,			NULL)
	PHP_FE(selinux_getpidcon,		NULL)
	PHP_FE(selinux_getprevcon,		NULL)
	PHP_FE(selinux_getexeccon,		NULL)
	PHP_FE(selinux_setexeccon,		NULL)
	PHP_FE(selinux_getfscreatecon,		NULL)
	PHP_FE(selinux_setfscreatecon,		NULL)
	PHP_FE(selinux_getkeycreatecon,		NULL)
	PHP_FE(selinux_setkeycreatecon,		NULL)
	PHP_FE(selinux_getsockcreatecon,	NULL)
	PHP_FE(selinux_setsockcreatecon,	NULL)

	/* get/set file context */
	PHP_FE(selinux_getfilecon,		NULL)
	PHP_FE(selinux_lgetfilecon,		NULL)
	PHP_FE(selinux_fgetfilecon,		NULL)

	PHP_FE(selinux_setfilecon,		NULL)
	PHP_FE(selinux_lsetfilecon,		NULL)
	PHP_FE(selinux_fsetfilecon,		NULL)

	/* labeled networking  */
	PHP_FE(selinux_getpeercon,		NULL)

	/* security_compute_XXXX() wrappers */
	PHP_FE(selinux_compute_av,		NULL)
	PHP_FE(selinux_compute_create,		NULL)
	PHP_FE(selinux_compute_relabel,		NULL)
	PHP_FE(selinux_compute_member,		NULL)
	PHP_FE(selinux_compute_user,		NULL)

	/* get initial context */
	PHP_FE(selinux_get_initial_context,	NULL)

	/* sanity check in security context */
	PHP_FE(selinux_check_context,		NULL)
	PHP_FE(selinux_canonicalize_context,	NULL)

	/* booleans */
	PHP_FE(selinux_get_boolean_names,	NULL)
	PHP_FE(selinux_get_boolean_pending,	NULL)
	PHP_FE(selinux_get_boolean_active,	NULL)
	PHP_FE(selinux_set_boolean,		NULL)
	PHP_FE(selinux_commit_booleans,		NULL)

	/* mcstrans */
	PHP_FE(selinux_trans_to_raw_context,	NULL)
	PHP_FE(selinux_raw_to_trans_context,	NULL)

	/* matchpathcon */
	PHP_FE(selinux_matchpathcon,		NULL)
	PHP_FE(selinux_lsetfilecon_default,	NULL)

	/* configuration files */
	PHP_FE(selinux_getenforcemode,		NULL)
	PHP_FE(selinux_getpolicytype,		NULL)
	PHP_FE(selinux_policy_root,		NULL)

	{NULL, NULL, NULL},
};

/*
 * SELinux module entry
 */
zend_module_entry selinux_module_entry = {
	STANDARD_MODULE_HEADER,
	"selinux",
	selinux_functions,
	NULL,			/* module_startup_func */
	NULL,			/* module_shutdown_func */
	NULL,			/* request_startup_func */
	PHP_RSHUTDOWN(selinux),	/* request_shutdown_func */
	NULL,			/* info_func */
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES,
};

#ifdef COMPILE_DL_SELINUX
ZEND_GET_MODULE(selinux)
#endif

/*
 * SELinux module cleanups
 */
PHP_RSHUTDOWN_FUNCTION(selinux)
{
	matchpathcon_fini();

	return SUCCESS;
}

/* {{{ proto bool selinux_is_enabled(void)
   Returns 'true' if SELinux is working on the host. */
PHP_FUNCTION(selinux_is_enabled)
{
	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (is_selinux_enabled())
		RETURN_TRUE;
	RETURN_FALSE;
}
/* }}} */

/* {{{ proto bool selinux_mls_is_enabled(void)
   Returns 'true' if SELinux is working with MLS policy. */
PHP_FUNCTION(selinux_mls_is_enabled)
{
	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (is_selinux_mls_enabled())
		RETURN_TRUE;
	RETURN_FALSE;
}
/* }}} */

/* {{{ proto int selinux_getenforce(void)
   Returns the current state of SELinux enforcing/permissive mode */
PHP_FUNCTION(selinux_getenforce)
{
	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	RETURN_LONG(security_getenforce());
}
/* }}} */

/* {{{ proto bool selinux_setenforce(int mode)
   Sets the state of SELinux enforcing/permissive mode */
PHP_FUNCTION(selinux_setenforce)
{
	long mode;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                                  "l", &mode) == FAILURE)
                RETURN_FALSE;

	if (security_setenforce(mode))
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto int selinux_policyvers(void)
   Returns the version of the security policy in the kernel. */
PHP_FUNCTION(selinux_policyvers)
{
	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	RETURN_LONG(security_policyvers());
}
/* }}} */

/* {{{ proto string selinux_getcon(void)
   Returns the context of the current process. */
PHP_FUNCTION(selinux_getcon)
{
	security_context_t context;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (getcon(&context) < 0)
		RETURN_FALSE;

	if (!context)
		RETURN_EMPTY_STRING();
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_setcon(string context)
   Sets the context of the current process. */
PHP_FUNCTION(selinux_setcon)
{
	security_context_t context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		context = NULL;

	if (setcon(context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_getpidcon(long pid)
   Returns the context of the process for the specified PID. */
PHP_FUNCTION(selinux_getpidcon)
{
	security_context_t context;
	long pid;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "l", &pid) == FAILURE)
		RETURN_FALSE;

	if (getpidcon((pid_t) pid, &context) < 0)
		RETURN_FALSE;

	if (!context)
		RETURN_EMPTY_STRING();
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto string selinux_getprevcon(void)
   Returns the context of the process before the last execve(2). */
PHP_FUNCTION(selinux_getprevcon)
{
	security_context_t context;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (getprevcon(&context) < 0)
		RETURN_FALSE;

	if (!context)
		RETURN_EMPTY_STRING();
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto string selinux_getexeccon(void)
   Returns the context used for executing a new program. */
PHP_FUNCTION(selinux_getexeccon)
{
	security_context_t context;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (getexeccon(&context) < 0)
		RETURN_FALSE;

	if (!context)
		RETURN_EMPTY_STRING();
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_setexeccon(string context)
   Sets the context used for executing a new program. */
PHP_FUNCTION(selinux_setexeccon)
{
	security_context_t context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		context = NULL;

	if (setexeccon(context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_getfscreatecon(void)
   Returns the context used for executing a new program. */
PHP_FUNCTION(selinux_getfscreatecon)
{
	security_context_t context;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (getfscreatecon(&context) < 0)
		RETURN_FALSE;

	if (!context)
		RETURN_EMPTY_STRING();
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_setfscreatecon(string context)
   Sets the context used for creating a new file system object. */
PHP_FUNCTION(selinux_setfscreatecon)
{
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		context = NULL;

	if (setfscreatecon(context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_getkeycreatecon(void)
   Returns the context used for creating a new kernel keyring. */
PHP_FUNCTION(selinux_getkeycreatecon)
{
	security_context_t context;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (getkeycreatecon(&context) < 0)
		RETURN_FALSE;

	if (!context)
		RETURN_EMPTY_STRING();
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_setkeycreatecon(string context)
   Sets the context used for creating a new kernel keyring. */
PHP_FUNCTION(selinux_setkeycreatecon)
{
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		context = NULL;

	if (setkeycreatecon(context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_getsockcreatecon(void)
   Returns the context used for creating a new socket object. */
PHP_FUNCTION(selinux_getsockcreatecon)
{
	security_context_t context;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (getsockcreatecon(&context) < 0)
		RETURN_FALSE;

	if (!context)
		RETURN_EMPTY_STRING();
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_setsockcreatecon(string context)
   Sets the context used for creating a new socket object. */
PHP_FUNCTION(selinux_setsockcreatecon)
{
	security_context_t context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		context = NULL;

	if (setsockcreatecon(context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_getfilecon(string filename)
   Returns the context associated with the given filename. */
PHP_FUNCTION(selinux_getfilecon)
{
	security_context_t context;
	char *filename;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &filename, &length) == FAILURE)
		RETURN_FALSE;
	if (length == 0)
		RETURN_FALSE;

	if (getfilecon(filename, &context) < 0 || !context)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto string selinux_lgetfilecon(string filename)
   Identical to selinux_getfilecon, except in the case of a symbolic link. */
PHP_FUNCTION(selinux_lgetfilecon)
{
	security_context_t context;
	char *filename;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &filename, &length) == FAILURE)
		RETURN_FALSE;
	if (length == 0)
		RETURN_FALSE;

	if (lgetfilecon(filename, &context) < 0 || !context)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto string selinux_fgetfilecon(resource stream)
   Identical to selinux_getfilecon,  only the open file pointed to by stream. */
PHP_FUNCTION(selinux_fgetfilecon)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int fdesc;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "z", &z) == FAILURE)
		RETURN_FALSE;
	php_stream_from_zval_no_verify(stream, &z);

	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fdesc, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (fgetfilecon(fdesc, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_setfilecon(string filename, string context)
   Sets the security context of the file system object. */
PHP_FUNCTION(selinux_setfilecon)
{
	char *filename, *context;
	int filename_len, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &filename, &filename_len,
				  &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (filename_len == 0 || context_len == 0)
		RETURN_FALSE;

	if (setfilecon(filename, context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool selinux_lsetfilecon(string filename, string context)
   Identical to selinux_setfilecon, except in the case of a symbolic link. */
PHP_FUNCTION(selinux_lsetfilecon)
{
	char *filename, *context;
	int filename_len, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &filename, &filename_len,
				  &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (filename_len == 0 || context_len == 0)
		RETURN_FALSE;

	if (lsetfilecon(filename, context) < 0)
			RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool selinux_fsetfilecon(resource stream, string context)
   Identical to selinux_setfilecon, only the open file pointed to by stream. */
PHP_FUNCTION(selinux_fsetfilecon)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int fdesc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "zs", &z, &context, &context_len) == FAILURE)
		RETURN_FALSE;

	php_stream_from_zval_no_verify(stream, &z);
	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fdesc, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (fsetfilecon(fdesc, context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

/* proto string selinux_getpeercon(resource stream)
   Returns the context of the peer socket of given stream. */
PHP_FUNCTION(selinux_getpeercon)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int sockfd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z) == FAILURE)
		RETURN_FALSE;

	php_stream_from_zval_no_verify(stream, &z);
	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &sockfd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;
	if (getpeercon(sockfd, &context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto array selinux_compute_av(string scon, string tcon, srting tclass)
   Retutns the access vector for the given scon, tcon and tclass. */
PHP_FUNCTION(selinux_compute_av)
{
	char *scontext, *tcontext, *tclass_name;
	int scontext_len, tcontext_len, tclass_len;
	security_class_t tclass;
	access_vector_t perm;
	struct av_decision avd;
	zval *allowed, *auditallow, *auditdeny;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
				  &scontext, &scontext_len,
				  &tcontext, &tcontext_len,
				  &tclass_name, &tclass_len) == FAILURE)
		return;

	if (scontext_len == 0 || tcontext_len == 0 || tclass_len == 0)
		RETURN_FALSE;

	tclass = string_to_security_class(tclass_name);
	if (security_compute_av(scontext, tcontext, tclass, -1, &avd) < 0)
		RETURN_FALSE;

	MAKE_STD_ZVAL(allowed);
	MAKE_STD_ZVAL(auditallow);
	MAKE_STD_ZVAL(auditdeny);
	array_init(allowed);
	array_init(auditallow);
	array_init(auditdeny);

	for (perm = 1; perm; perm <<= 1)
	{
		char *perm_name = security_av_perm_to_string(tclass, perm);

		if (!perm_name)
			continue;

		add_assoc_bool(allowed, perm_name,
			       (avd.allowed & perm) ? 1 : 0);
		add_assoc_bool(auditallow, perm_name,
			       (avd.auditallow & perm) ? 1 : 0);
		add_assoc_bool(auditdeny, perm_name,
			       (avd.auditdeny & perm) ? 1 : 0);
	}

	array_init(return_value);
	add_assoc_zval(return_value, "allowed", allowed);
	add_assoc_zval(return_value, "auditallow", auditallow);
	add_assoc_zval(return_value, "auditdeny", auditdeny);
	add_assoc_long(return_value, "seqno", avd.seqno);
}
/* }}} */

/* {{{ proto string selinux_compute_create(string scon, string tcon, string tclass)
   Returns the context for a new object in a particular class and contexts. */
PHP_FUNCTION(selinux_compute_create)
{
	char *scontext, *tcontext, *tclass_name;
	int scontext_len, tcontext_len, tclass_len;
	security_context_t context;
	security_class_t tclass;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
				  &scontext, &scontext_len,
				  &tcontext, &tcontext_len,
				  &tclass_name, &tclass_len) == FAILURE)
		return;

	if (scontext_len == 0 || tcontext_len == 0 || tclass_len == 0)
		RETURN_FALSE;
	tclass = string_to_security_class(tclass_name);
	if (security_compute_create(scontext, tcontext, tclass, &context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto string selinux_compute_relabel(string scon, string tcon, string tclass)
   Returns the context used when an object is relabeled. */
PHP_FUNCTION(selinux_compute_relabel)
{
	char *scontext, *tcontext, *tclass_name;
	int scontext_len, tcontext_len, tclass_len;
	security_context_t context;
	security_class_t tclass;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
				  &scontext, &scontext_len,
				  &tcontext, &tcontext_len,
				  &tclass_name, &tclass_len) == FAILURE)
		return;

	if (scontext_len == 0 || tcontext_len == 0 || tclass_len == 0)
		RETURN_FALSE;
	tclass = string_to_security_class(tclass_name);
	if (security_compute_relabel(scontext, tcontext, tclass, &context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto string selinux_compute_member(string scon, string tcon, string tclass)
   Returns the context to use when labeling a polyinstantiated object instance. */
PHP_FUNCTION(selinux_compute_member)
{
	char *scontext, *tcontext, *tclass_name;
	int scontext_len, tcontext_len, tclass_len;
	security_context_t context;
	security_class_t tclass;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
				  &scontext, &scontext_len,
				  &tcontext, &tcontext_len,
				  &tclass_name, &tclass_len) == FAILURE)
		return;

	if (scontext_len == 0 || tcontext_len == 0 || tclass_len == 0)
		RETURN_FALSE;
	tclass = string_to_security_class(tclass_name);
	if (security_compute_member(scontext, tcontext, tclass, &context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto array selinux_compute_user(string scon, string username)
   Returns a set of user contexts that can be reached from a source context. */
PHP_FUNCTION(selinux_compute_user)
{
	char *scontext, *username;
	int scontext_len, username_len;
	security_context_t *contexts;
	int i;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &scontext, &scontext_len,
				  &username, &username_len) == FAILURE)
		RETURN_FALSE;
	if (scontext_len == 0 || username_len == 0)
		RETURN_FALSE;
	if (security_compute_user(scontext, username, &contexts) < 0)
		RETURN_FALSE;

	array_init(return_value);
	for (i=0; contexts[i]; i++)
	{
		add_next_index_string(return_value, contexts[i], 1);
	}
	freeconary(contexts);
}
/* }}} */

/* {{{ proto string selinux_get_initial_context(string name)
   Returns the context of a kernel initial security identifier specified by name.*/
PHP_FUNCTION(selinux_get_initial_context)
{
	char *name;
	int length;
	security_context_t context;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &name, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		RETURN_FALSE;

	if (security_get_initial_context(name, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_check_context(string context)
   Checks whether the given context is valid, or not. */
PHP_FUNCTION(selinux_check_context)
{
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		RETURN_FALSE;

	if (security_check_context(context) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_canonicalize_context(string context)
   Returns canonicalized context if the given one is valid. */
PHP_FUNCTION(selinux_canonicalize_context)
{
	security_context_t canonicalized;
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (length == 0)
		RETURN_FALSE;

	if (security_canonicalize_context(context, &canonicalized) < 0)
		RETURN_FALSE;

	RETVAL_STRING(canonicalized, 1);
        freecon(canonicalized);
}
/* }}} */

/* {{{ proto array selinux_get_boolean_names(void)
   Returns a list of boolean name, supported by the working policy. */
PHP_FUNCTION(selinux_get_boolean_names)
{
	char **bool_names;
	int i, length;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (security_get_boolean_names(&bool_names, &length) < 0)
		RETURN_FALSE;

	array_init(return_value);
	for (i=0; i < length; i++) {
		add_next_index_string(return_value, bool_names[i], 1);
		free(bool_names[i]);
	}
	free(bool_names);
}
/* }}} */

/* {{{ proto int selinux_get_boolean_pending(string bool_name)
   Returns a pending value for boolean specified in bool_name. */
PHP_FUNCTION(selinux_get_boolean_pending)
{
	char *bool_name;
	int length;
	long value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				  &bool_name, &length) == FAILURE)
		RETURN_LONG(-1);

	value = security_get_boolean_pending(bool_name);
	RETURN_LONG(value);
}
/* }}} */

/* {{{ proto int selinux_get_boolean_active(string bool_name)
   Returns an active value for boolean specified in bool_name. */
PHP_FUNCTION(selinux_get_boolean_active)
{
	char *bool_name;
	int length;
	long value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				  &bool_name, &length) == FAILURE)
		RETURN_LONG(-1);

	value = security_get_boolean_active(bool_name);
	RETURN_LONG(value);
}
/* }}} */

/* {{{ proto bool selinux_set_boolean(string bool_name, bool value)
   Sets the pending value for boolean specified in bool_name.*/
PHP_FUNCTION(selinux_set_boolean)
{
	char *bool_name;
	int length;
	zend_bool new_value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sb",
				  &bool_name, &length, &new_value) == FAILURE)
		RETURN_FALSE;

	if (security_set_boolean(bool_name, new_value) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool selinux_commit_booleans(void)
   Commits all the pending values for booleans. */
PHP_FUNCTION(selinux_commit_booleans)
{
	if (security_commit_booleans() < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_trans_to_raw_context(string context)
   Translate a human-readable context into internal system format.*/
PHP_FUNCTION(selinux_trans_to_raw_context)
{
	security_context_t raw_context;
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;
	if (length == 0)
		RETURN_FALSE;
	if (selinux_trans_to_raw_context(context, &raw_context) < 0 || !raw_context)
		RETURN_FALSE;
	RETVAL_STRING(raw_context, 1);
	freecon(raw_context);
}
/* }}} */

/* {{{ proto string selinux_raw_to_trans_context(string context)
   Translate a human-readable context from internal system format. */
PHP_FUNCTION(selinux_raw_to_trans_context)
{
	security_context_t trans_context;
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;
	if (length == 0)
		RETURN_FALSE;
	if (selinux_raw_to_trans_context(context, &trans_context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(trans_context, 1);
	freecon(trans_context);
}
/* }}} */

/* {{{ string selinux_matchpathcon(string path [, int mode
                                               [, bool base_only
                                               [, bool validate]]])
   Returns the security context configured on the given path.
*/
PHP_FUNCTION(selinux_matchpathcon)
{
	security_context_t context;
	char *path;
	int length;
	long mode = 0;
	zend_bool baseonly = 0;
	zend_bool validate = 0;
	unsigned int flags = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lbb",
				  &path, &length,
				  &mode, &baseonly, &validate) == FAILURE)
		RETURN_FALSE;
	if (length == 0)
		RETURN_FALSE;
	if (baseonly)
		flags |= MATCHPATHCON_BASEONLY;
	if (validate)
		flags |= MATCHPATHCON_VALIDATE;

	set_matchpathcon_flags(flags);

	mode &= S_IFMT;
	if (matchpathcon(path, mode, &context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}
/* }}} */

/* {{{ proto bool selinux_lsetfilecon_default(string filename)
   Sets the file context on to the system defaults. */
PHP_FUNCTION(selinux_lsetfilecon_default)
{
	char *filename;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				  &filename, &length) == FAILURE)
		RETURN_FALSE;
	if (length == 0)
		RETURN_FALSE;
	if (selinux_lsetfilecon_default(filename) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string selinux_getenforcemode(void)
   Returns the initial state on the system, configured in /etc/selinux/config. */
PHP_FUNCTION(selinux_getenforcemode)
{
	int enforce;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();
	if (selinux_getenforcemode(&enforce))
		RETURN_FALSE;

	if (enforce > 0) {
		RETVAL_STRING("enforcing", 1);
	} else if (enforce < 0) {
		RETVAL_STRING("disabled", 1);
	} else {
		RETVAL_STRING("permissive", 1);
	}
}
/* }}} */

/* {{{ proto string selinux_getpolicytype(void)
   Returns the default policy type on the system, configured in /etc/selinux/config. */
PHP_FUNCTION(selinux_getpolicytype)
{
	char *policytype;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();
	if (selinux_getpolicytype(&policytype) < 0)
		RETURN_FALSE;
	RETVAL_STRING(policytype, 1);
	free(policytype);
}
/* }}} */

/* {{{ proto string selinux_policy_root(void)
   Returns the directory path which stores the policy and context configuration. */
PHP_FUNCTION(selinux_policy_root)
{
	const char *root = selinux_policy_root();

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();
	RETVAL_STRING(root, 1);
}
/* }}} */

#endif	/* HAVE_SELINUX */
