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
	/*  wrappers for the /proc/pid/attr API */
	PHP_FE(selinux_is_enabled,		NULL)
	PHP_FE(selinux_mls_is_enabled,		NULL)
	PHP_FE(selinux_getcon,			NULL)
	PHP_FE(selinux_getcon_raw,		NULL)
	PHP_FE(selinux_setcon,			NULL)
	PHP_FE(selinux_setcon_raw,		NULL)
	PHP_FE(selinux_getpidcon,		NULL)
	PHP_FE(selinux_getpidcon_raw,		NULL)
	PHP_FE(selinux_getprevcon,		NULL)
	PHP_FE(selinux_getexeccon,		NULL)
	PHP_FE(selinux_getexeccon_raw,		NULL)
	PHP_FE(selinux_setexeccon,		NULL)
	PHP_FE(selinux_setexeccon_raw,		NULL)
	PHP_FE(selinux_getfscreatecon,		NULL)
	PHP_FE(selinux_getfscreatecon_raw,	NULL)
	PHP_FE(selinux_setfscreatecon,		NULL)
	PHP_FE(selinux_setfscreatecon_raw,	NULL)
	PHP_FE(selinux_getkeycreatecon,		NULL)
	PHP_FE(selinux_getkeycreatecon_raw,	NULL)
	PHP_FE(selinux_setkeycreatecon,		NULL)
	PHP_FE(selinux_setkeycreatecon_raw,	NULL)
	PHP_FE(selinux_getsockcreatecon,	NULL)
	PHP_FE(selinux_getsockcreatecon_raw,	NULL)
	PHP_FE(selinux_setsockcreatecon,	NULL)
	PHP_FE(selinux_setsockcreatecon_raw,	NULL)

	/* get/set file context */
	PHP_FE(selinux_getfilecon,		NULL)
	PHP_FE(selinux_getfilecon_raw,		NULL)
	PHP_FE(selinux_lgetfilecon,		NULL)
	PHP_FE(selinux_lgetfilecon_raw,		NULL)
	PHP_FE(selinux_fgetfilecon,		NULL)
	PHP_FE(selinux_fgetfilecon_raw,		NULL)

	PHP_FE(selinux_setfilecon,		NULL)
	PHP_FE(selinux_setfilecon_raw,		NULL)
	PHP_FE(selinux_lsetfilecon,		NULL)
	PHP_FE(selinux_lsetfilecon_raw,		NULL)
	PHP_FE(selinux_fsetfilecon,		NULL)
	PHP_FE(selinux_fsetfilecon_raw,		NULL)

	/* labeled networking  */
	PHP_FE(selinux_getpeercon,		NULL)
	PHP_FE(selinux_getpeercon_raw,		NULL)

	/* get initial context */
	PHP_FE(selinux_get_initial_context,	NULL)
	PHP_FE(selinux_get_initial_context_raw,	NULL)

	/* sanity check in security context */
	PHP_FE(selinux_check_context,		NULL)
	PHP_FE(selinux_check_context_raw,	NULL)
	PHP_FE(selinux_canonicalize_context,	NULL)
	PHP_FE(selinux_canonicalize_context_raw,NULL)

	/* global setting related */
	PHP_FE(selinux_getenforce,		NULL)
	PHP_FE(selinux_setenforce,		NULL)
	PHP_FE(selinux_policyvers,		NULL)

	/* booleans */
	PHP_FE(selinux_get_boolean_names,	NULL)
	PHP_FE(selinux_get_boolean_pending,	NULL)
	PHP_FE(selinux_get_boolean_active,	NULL)
	PHP_FE(selinux_set_boolean,		NULL)
	PHP_FE(selinux_commit_booleans,		NULL)

	/* mcstrans */
	PHP_FE(selinux_trans_to_raw_context,	NULL)
	PHP_FE(selinux_raw_to_trans_context,	NULL)

	{NULL, NULL, NULL},
};

/*
 * SELinux module entry
 */
zend_module_entry selinux_module_entry = {
	STANDARD_MODULE_HEADER,
	"selinux",
	selinux_functions,
	NULL,		/* module_startup_func */
	NULL,		/* module_shutdown_func */
	NULL,		/* request_startup_func */
	NULL,		/* request_shutdown_func */
	NULL,		/* info_func */
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES,
};

#ifdef COMPILE_DL_SYSVSEM
ZEND_GET_MODULE(selinux)
#endif

PHP_MINIT_FUNCTION(selinux)
{
	return SUCCESS;
}

PHP_FUNCTION(selinux_is_enabled)
{
	if (is_selinux_enabled())
		RETURN_TRUE;
	RETURN_FALSE;
}

PHP_FUNCTION(selinux_mls_is_enabled)
{
	if (is_selinux_mls_enabled())
		RETURN_TRUE;
	RETURN_FALSE;
}

/*
 * Wrappers for the /proc/pid/attr API.
 */
PHP_FUNCTION(selinux_getcon)
{
	security_context_t context;

	if (getcon(&context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getcon_raw)
{
	security_context_t context;

	if (getcon_raw(&context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_setcon)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setcon(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setcon_raw)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (setcon_raw(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_getpidcon)
{
	security_context_t context;
	long pid;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "l", &pid) == FAILURE
	    || getpidcon((pid_t) pid, &context) < 0)


	if (getpidcon((pid_t) pid, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
        freecon(context);
}

PHP_FUNCTION(selinux_getpidcon_raw)
{
	security_context_t context;
	long pid;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "l", &pid) == FAILURE)
		RETURN_FALSE;

	if (getpidcon_raw((pid_t) pid, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
        freecon(context);
}

PHP_FUNCTION(selinux_getprevcon)
{
	security_context_t context;

	if (getprevcon(&context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getprevcon_raw)
{
	security_context_t context;

	if (getprevcon_raw(&context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getexeccon)
{
	security_context_t context;

	if (getexeccon(&context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getexeccon_raw)
{
	security_context_t context;

	if (getexeccon_raw(&context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_setexeccon)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setexeccon(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setexeccon_raw)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setexeccon_raw(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_getfscreatecon)
{
	security_context_t context;

	if (getfscreatecon(&context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getfscreatecon_raw)
{
	security_context_t context;

	if (getfscreatecon_raw(&context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_setfscreatecon)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setfscreatecon(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setfscreatecon_raw)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setfscreatecon_raw(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_getkeycreatecon)
{
	security_context_t context;

	if (getkeycreatecon(&context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getkeycreatecon_raw)
{
	security_context_t context;

	if (getkeycreatecon_raw(&context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_setkeycreatecon)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setkeycreatecon(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setkeycreatecon_raw)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setkeycreatecon_raw(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_getsockcreatecon)
{
	security_context_t context;

	if (getsockcreatecon(&context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getsockcreatecon_raw)
{
	security_context_t context;

	if (getsockcreatecon_raw(&context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_setsockcreatecon)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setsockcreatecon(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setsockcreatecon_raw)
{
	char *context;
	int context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;
	if (setsockcreatecon_raw(context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

/*
 * Get file context
 */
PHP_FUNCTION(selinux_getfilecon)
{
	char *filename;
	int filename_len;
	security_context_t context;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &filename, &filename_len) == FAILURE)
		RETURN_FALSE;

	if (getfilecon(filename, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getfilecon_raw)
{
	char *filename;
	int filename_len;
	security_context_t context;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &filename, &filename_len) == FAILURE)
		RETURN_FALSE;

	if (getfilecon(filename, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_lgetfilecon)
{
	char *filename;
	int filename_len;
	security_context_t context;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &filename, &filename_len) == FAILURE)
		RETURN_FALSE;

	if (lgetfilecon(filename, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_lgetfilecon_raw)
{
	char *filename;
	int filename_len;
	security_context_t context;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &filename, &filename_len) == FAILURE)
		RETURN_FALSE;

	if (lgetfilecon_raw(filename, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_fgetfilecon)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int fd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z) == FAILURE)
		RETURN_FALSE;
	php_stream_from_zval_no_verify(stream, &z);

	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (fgetfilecon(fd, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_fgetfilecon_raw)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int fd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z) == FAILURE)
		RETURN_FALSE;
	php_stream_from_zval_no_verify(stream, &z);

	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (fgetfilecon_raw(fd, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

/*
 * Set file context
 */
PHP_FUNCTION(selinux_setfilecon)
{
	char *filename, *context;
	int filename_len, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &filename, &filename_len,
				  &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (setfilecon(filename, context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setfilecon_raw)
{
	char *filename, *context;
	int filename_len, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &filename, &filename_len,
				  &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (setfilecon_raw(filename, context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_lsetfilecon)
{
	char *filename, *context;
	int filename_len, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &filename, &filename_len,
				  &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (lsetfilecon(filename, context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_lsetfilecon_raw)
{
	char *filename, *context;
	int filename_len, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &filename, &filename_len,
				  &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (lsetfilecon_raw(filename, context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_fsetfilecon)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int fd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "zs", &z, &context) == FAILURE)
		RETURN_FALSE;

	php_stream_from_zval_no_verify(stream, &z);
	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (fsetfilecon(fd, context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

PHP_FUNCTION(selinux_fsetfilecon_raw)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int fd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "zs", &z, &context) == FAILURE)
		RETURN_FALSE;

	php_stream_from_zval_no_verify(stream, &z);
	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (fsetfilecon_raw(fd, context) < 0)
		RETURN_FALSE;

	RETURN_TRUE;
}

/*
 * Labeled Networking
 */
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

PHP_FUNCTION(selinux_getpeercon_raw)
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

	if (getpeercon_raw(sockfd, &context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

/*
 * get initial context
 */
PHP_FUNCTION(selinux_get_initial_context)
{}

PHP_FUNCTION(selinux_get_initial_context_raw)
{}

/*
 * sanity check in security context
 */
PHP_FUNCTION(selinux_check_context)
{}

PHP_FUNCTION(selinux_check_context_raw)
{}

PHP_FUNCTION(selinux_canonicalize_context)
{}

PHP_FUNCTION(selinux_canonicalize_context_raw)
{}

/*
 * global setting related
 */
PHP_FUNCTION(selinux_getenforce)
{}

PHP_FUNCTION(selinux_setenforce)
{}

PHP_FUNCTION(selinux_policyvers)
{}

/*
 * booleans
 */
PHP_FUNCTION(selinux_get_boolean_names)
{}

PHP_FUNCTION(selinux_get_boolean_pending)
{}

PHP_FUNCTION(selinux_get_boolean_active)
{}

PHP_FUNCTION(selinux_set_boolean)
{}

PHP_FUNCTION(selinux_commit_booleans)
{}

/*
 * mcstrans
 */
PHP_FUNCTION(selinux_trans_to_raw_context)
{}

PHP_FUNCTION(selinux_raw_to_trans_context)
{}

#endif	/* HAVE_SELINUX */
