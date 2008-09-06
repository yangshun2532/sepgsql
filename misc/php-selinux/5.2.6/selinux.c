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

#if HAVE_SOCKETS
	/* labeled networking  */
	PHP_FE(selinux_getpeercon,		NULL)
	PHP_FE(selinux_getpeercon_raw,		NULL)
#endif

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
	
}

PHP_FUNCTION(selinux_fgetfilecon_raw)
{
	
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
{}

PHP_FUNCTION(selinux_fsetfilecon_raw)
{}

#if HAVE_SOCKETS
/*
 * Labeled Networking
 */
PHP_FUNCTION(selinux_getpeercon)
{}

PHP_FUNCTION(selinux_getpeercon_raw)
{}
#endif

#endif	/* HAVE_SELINUX */
