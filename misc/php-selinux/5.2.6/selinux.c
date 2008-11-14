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

	/* security_compute_XXXX() wrappers */
	PHP_FE(selinux_compute_av,		NULL)
	PHP_FE(selinux_compute_av_raw,		NULL)
	PHP_FE(selinux_compute_create,		NULL)
	PHP_FE(selinux_compute_create_raw,	NULL)
	PHP_FE(selinux_compute_relabel,		NULL)
	PHP_FE(selinux_compute_relabel_raw,	NULL)
	PHP_FE(selinux_compute_member,		NULL)
	PHP_FE(selinux_compute_member_raw,	NULL)
	PHP_FE(selinux_compute_user,		NULL)
	PHP_FE(selinux_compute_user_raw,	NULL)

	/* get initial context */
	PHP_FE(selinux_get_initial_context,	NULL)
	PHP_FE(selinux_get_initial_context_raw,	NULL)

	/* sanity check in security context */
	PHP_FE(selinux_check_context,		NULL)
	PHP_FE(selinux_check_context_raw,	NULL)
	PHP_FE(selinux_canonicalize_context,	NULL)
	PHP_FE(selinux_canonicalize_context_raw,NULL)

	/* booleans */
	PHP_FE(selinux_get_boolean_names,	NULL)
	PHP_FE(selinux_get_boolean_pending,	NULL)
	PHP_FE(selinux_get_boolean_active,	NULL)
	PHP_FE(selinux_set_boolean,		NULL)
	PHP_FE(selinux_commit_booleans,		NULL)

	/* security class/access vector mapping */
	PHP_FE(selinux_string_to_class,		NULL)
	PHP_FE(selinux_class_to_string,		NULL)
	PHP_FE(selinux_av_perm_to_string,	NULL)
	PHP_FE(selinux_string_to_av_perm,	NULL)
	PHP_FE(selinux_av_string,		NULL)

	/* mcstrans */
	PHP_FE(selinux_trans_to_raw_context,	NULL)
	PHP_FE(selinux_raw_to_trans_context,	NULL)

	/* matchpathcon */
	PHP_FE(selinux_matchpathcon,		NULL)
	PHP_FE(selinux_matchpathcon_raw,	NULL)
	PHP_FE(selinux_lsetfilecon_default,	NULL)

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

#ifdef COMPILE_DL_SYSVSEM
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

/*
 * Global state APIs
 */
PHP_FUNCTION(selinux_is_enabled)
{
	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (is_selinux_enabled())
		RETURN_TRUE;
	RETURN_FALSE;
}

PHP_FUNCTION(selinux_mls_is_enabled)
{
	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (is_selinux_mls_enabled())
		RETURN_TRUE;
	RETURN_FALSE;
}

PHP_FUNCTION(selinux_getenforce)
{
	int rc;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	rc = security_getenforce();

	RETURN_LONG(rc);
}

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

PHP_FUNCTION(selinux_policyvers)
{
	int policyvers;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	policyvers = security_policyvers();

	RETURN_LONG(policyvers);
}

/*
 * Wrappers for the /proc/pid/attr API.
 */
static void do_selinux_getcon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	int rc;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (!raw)
		rc = getcon(&context);
	else
		rc = getcon_raw(&context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getcon)
{
	do_selinux_getcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getcon_raw)
{
	do_selinux_getcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_setcon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *context;
	int rc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = setcon(context);
	else
		rc = setcon_raw(context);

	if (rc < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setcon)
{
	do_selinux_setcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_setcon_raw)
{
	do_selinux_setcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_getpidcon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	long pid;
	int rc;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "l", &pid) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = getpidcon((pid_t) pid, &context);
	else
		rc = getpidcon_raw((pid_t) pid, &context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getpidcon)
{
	do_selinux_getpidcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getpidcon_raw)
{
	do_selinux_getpidcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_getprevcon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	int rc;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (!raw)
		rc = getprevcon(&context);
	else
		rc = getprevcon_raw(&context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getprevcon)
{
	do_selinux_getprevcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getprevcon_raw)
{
	do_selinux_getprevcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_getexeccon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	int rc;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (!raw)
		rc = getexeccon(&context);
	else
		rc = getexeccon_raw(&context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getexeccon)
{
	do_selinux_getexeccon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getexeccon_raw)
{
	do_selinux_getexeccon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_setexeccon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *context;
	int rc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (context_len == 0)
		context = NULL;

	if (!raw)
		rc = setexeccon(context);
	else
		rc = setexeccon_raw(context);
	if (rc < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setexeccon)
{
	do_selinux_setexeccon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_setexeccon_raw)
{
	do_selinux_getexeccon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_getfscreatecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	int rc;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (!raw)
		rc = getfscreatecon(&context);
	else
		rc = getfscreatecon_raw(&context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getfscreatecon)
{
	do_selinux_getfscreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getfscreatecon_raw)
{
	do_selinux_getfscreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_setfscreatecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *context;
	int rc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (context_len == 0)
		context = NULL;

	if (!raw)
		rc = setfscreatecon(context);
	else
		rc = setfscreatecon_raw(context);

	if (rc < 0)
		RETURN_FALSE;
        RETURN_TRUE;
}

PHP_FUNCTION(selinux_setfscreatecon)
{
	do_selinux_setfscreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_setfscreatecon_raw)
{
	do_selinux_setfscreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_getkeycreatecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	int rc;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (!raw)
		rc = getkeycreatecon(&context);
	else
		rc = getkeycreatecon_raw(&context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getkeycreatecon)
{
	do_selinux_getkeycreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getkeycreatecon_raw)
{
	do_selinux_getkeycreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_setkeycreatecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *context;
	int rc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (context_len == 0)
		context = NULL;

	if (!raw)
		rc = setkeycreatecon(context);
	else
		rc = setkeycreatecon_raw(context);

	if (rc < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setkeycreatecon)
{
	do_selinux_setkeycreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_setkeycreatecon_raw)
{
	do_selinux_setkeycreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_getsockcreatecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	int rc;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (!raw)
		rc = getsockcreatecon(&context);
	else
		rc = getsockcreatecon_raw(&context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getsockcreatecon)
{
	do_selinux_getsockcreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getsockcreatecon_raw)
{
	do_selinux_getsockcreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_setsockcreatecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *context;
	int rc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (context_len == 0)
		context = NULL;

	if (!raw)
		rc = setsockcreatecon(context);
	else
		rc = setsockcreatecon_raw(context);

	if (rc < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setsockcreatecon)
{
	do_selinux_setsockcreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_setsockcreatecon_raw)
{
	do_selinux_setsockcreatecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/*
 * Get file context
 */
static void do_selinux_getfilecon(INTERNAL_FUNCTION_PARAMETERS, int raw, int link)
{
	char *filename;
	int rc, filename_len;
	security_context_t context;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &filename, &filename_len) == FAILURE)
		RETURN_FALSE;

	if (!link) {
		if (!raw)
			rc = getfilecon(filename, &context);
		else
			rc = getfilecon_raw(filename, &context);
	} else {
		if (!raw)
			rc = lgetfilecon(filename, &context);
		else
			rc = lgetfilecon_raw(filename, &context);
	}
	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getfilecon)
{
	do_selinux_getfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0, 0);
}

PHP_FUNCTION(selinux_getfilecon_raw)
{
	do_selinux_getfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1, 0);
}

PHP_FUNCTION(selinux_lgetfilecon)
{
	do_selinux_getfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0, 1);
}

PHP_FUNCTION(selinux_lgetfilecon_raw)
{
	do_selinux_getfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1, 1);
}

static void do_selinux_fgetfilecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int rc, fd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z) == FAILURE)
		RETURN_FALSE;
	php_stream_from_zval_no_verify(stream, &z);

	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (!raw)
		rc = fgetfilecon(fd, &context);
	else
		rc = fgetfilecon_raw(fd, &context);

	if (rc < 0 || !context)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_fgetfilecon)
{
	do_selinux_fgetfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_fgetfilecon_raw)
{
	do_selinux_fgetfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/*
 * Set file context
 */
static void do_selinux_setfilecon(INTERNAL_FUNCTION_PARAMETERS, int raw, int link)
{
	char *filename, *context;
	int rc, filename_len, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &filename, &filename_len,
				  &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (!link) {
		if (!raw)
			rc = setfilecon(filename, context);
		else
			rc = setfilecon_raw(filename, context);
	} else {
		if (!raw)
			rc = lsetfilecon(filename, context);
		else
			rc = lsetfilecon_raw(filename, context);
	}

	if (rc < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

PHP_FUNCTION(selinux_setfilecon)
{
	do_selinux_setfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0, 0);
}

PHP_FUNCTION(selinux_setfilecon_raw)
{
	do_selinux_setfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1, 0);
}

PHP_FUNCTION(selinux_lsetfilecon)
{
	do_selinux_setfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0, 1);
}

PHP_FUNCTION(selinux_lsetfilecon_raw)
{
	do_selinux_setfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1, 1);
}

static void do_selinux_fsetfilecon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int rc, fd, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
							  "zs", &z, &context, &context_len) == FAILURE)
		RETURN_FALSE;

	php_stream_from_zval_no_verify(stream, &z);
	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &fd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (!raw)
		rc = fsetfilecon(fd, context);
	else
		rc = fsetfilecon_raw(fd, context);

	if (rc < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}
PHP_FUNCTION(selinux_fsetfilecon)
{
	do_selinux_fsetfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_fsetfilecon_raw)
{
	do_selinux_fsetfilecon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/*
 * Labeled Networking
 */
static void do_selinux_getpeercon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	zval *z;
	php_stream *stream;
	security_context_t context;
	int rc, sockfd;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &z) == FAILURE)
		RETURN_FALSE;

	php_stream_from_zval_no_verify(stream, &z);
	if (!stream)
		RETURN_FALSE;

	if (php_stream_cast(stream, PHP_STREAM_AS_FD,
			    (void **) &sockfd, REPORT_ERRORS) != SUCCESS)
		RETURN_FALSE;

	if (!raw)
		rc = getpeercon(sockfd, &context);
	else
		rc = getpeercon_raw(sockfd, &context);

	if (rc < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_getpeercon)
{
	do_selinux_getpeercon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_getpeercon_raw)
{
	do_selinux_getpeercon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/*
 * security_compute_XXXX() wrappers
 */
static void do_selinux_compute_av(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *scon, *tcon;
	int rc, scon_len, tcon_len;
	long tclass;
	struct av_decision avd;

        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl",
				  &scon, &scon_len,
				  &tcon, &tcon_len, &tclass) == FAILURE)
		RETURN_FALSE;
	if (!raw)
		rc = security_compute_av(scon, tcon, tclass, -1, &avd);
	else
		rc = security_compute_av_raw(scon, tcon, tclass, -1, &avd);

	if (rc < 0)
		RETURN_FALSE;

	array_init(return_value);
	add_assoc_long(return_value, "allowed",    avd.allowed);
	add_assoc_long(return_value, "decided",    avd.decided);
	add_assoc_long(return_value, "auditallow", avd.auditallow);
	add_assoc_long(return_value, "auditdeny",  avd.auditdeny);
	add_assoc_long(return_value, "seqno",      avd.seqno);
}

PHP_FUNCTION(selinux_compute_av)
{
	do_selinux_compute_av(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_compute_av_raw)
{
	do_selinux_compute_av(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_compute_create(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	char *scon, *tcon;
	int rc, scon_len, tcon_len;
	long tclass;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl",
				  &scon, &scon_len,
				  &tcon, &tcon_len, &tclass) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = security_compute_create(scon, tcon, tclass, &context);
	else
		rc = security_compute_create_raw(scon, tcon, tclass, &context);

	if (rc < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_compute_create)
{
	do_selinux_compute_create(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_compute_create_raw)
{
	do_selinux_compute_create(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_compute_relabel(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	char *scon, *tcon;
	int rc, scon_len, tcon_len;
	long tclass;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl",
				  &scon, &scon_len,
				  &tcon, &tcon_len, &tclass) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = security_compute_relabel(scon, tcon, tclass, &context);
	else
		rc = security_compute_relabel_raw(scon, tcon, tclass, &context);

	if (rc < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_compute_relabel)
{
	do_selinux_compute_relabel(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_compute_relabel_raw)
{
	do_selinux_compute_relabel(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_compute_member(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	char *scon, *tcon;
	int rc, scon_len, tcon_len;
	long tclass;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssl",
				  &scon, &scon_len,
				  &tcon, &tcon_len, &tclass) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = security_compute_member(scon, tcon, tclass, &context);
	else
		rc = security_compute_member_raw(scon, tcon, tclass, &context);

	if (rc < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_compute_member)
{
	do_selinux_compute_member(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_compute_member_raw)
{
	do_selinux_compute_member(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static void do_selinux_compute_user(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t *contexts;
	char *scon, *username;
	int i, rc, scon_len, username_len;
	long tclass;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				  &scon, &scon_len,
				  &username, &username_len) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = security_compute_user(scon, username, &contexts);
	else
		rc = security_compute_user_raw(scon, username, &contexts);

	if (rc < 0)
		RETURN_FALSE;

	array_init(return_value);
	for (i=0; contexts[i]; i++)
	{
		add_next_index_string(return_value, contexts[i], 1);
	}
	freeconary(contexts);
}

PHP_FUNCTION(selinux_compute_user)
{
	do_selinux_compute_user(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_compute_user_raw)
{
	do_selinux_compute_user(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/*
 * get initial context
 */
static void do_selinux_get_initial_context(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *name;
	int rc, length;
	security_context_t context;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &name, &length) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = security_get_initial_context(name, &context);
	else
		rc = security_get_initial_context_raw(name, &context);

	if (rc < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_get_initial_context)
{
	do_selinux_get_initial_context(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_get_initial_context_raw)
{
	do_selinux_get_initial_context(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/*
 * sanity check in security context
 */
static void do_selinux_check_context(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	char *context;
	int rc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = security_check_context(context);
	else
		rc = security_check_context_raw(context);

	if (rc < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

PHP_FUNCTION(selinux_check_context)
{
	do_selinux_check_context(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_check_context_raw)
{
	do_selinux_check_context(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

static do_selinux_canonicalize_context(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t canonicalized;
	char *context;
	int rc, context_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &context_len) == FAILURE)
		RETURN_FALSE;

	if (!raw)
		rc = security_canonicalize_context(context, &canonicalized);
	else
		rc = security_canonicalize_context_raw(context, &canonicalized);

	if (rc < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
        freecon(context);
}

PHP_FUNCTION(selinux_canonicalize_context)
{
	do_selinux_canonicalize_context(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_canonicalize_context_raw)
{
	do_selinux_canonicalize_context(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

/*
 * booleans
 */
PHP_FUNCTION(selinux_get_boolean_names)
{
	char **bool_names;
	int i, len;

	if (ZEND_NUM_ARGS() != 0)
		ZEND_WRONG_PARAM_COUNT();

	if (security_get_boolean_names(&bool_names, &len) < 0)
		RETURN_FALSE;

	array_init(return_value);
	for (i=0; i < len; i++) {
		add_next_index_string(return_value, bool_names[i], 1);
		free(bool_names[i]);
	}
	free(bool_names);
}

PHP_FUNCTION(selinux_get_boolean_pending)
{
	char *bool_name;
	int length;
	long value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				  &bool_name, &length) == FAILURE)
		RETURN_FALSE;

	value = security_get_boolean_pending(bool_name);

	RETURN_LONG(value);
}

PHP_FUNCTION(selinux_get_boolean_active)
{
	char *bool_name;
	int length;
	long value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				  &bool_name, &length) == FAILURE)
		RETURN_FALSE;

	value = security_get_boolean_active(bool_name);

	RETURN_LONG(value);
}

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

PHP_FUNCTION(selinux_commit_booleans)
{
	if (security_commit_booleans() < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

/*
 * security class/access vector mapping
 */
PHP_FUNCTION(selinux_string_to_class)
{
	security_class_t tclass;
	char *tclass_name;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				  &tclass_name, &length) == FAILURE)
		RETURN_FALSE;

	tclass = string_to_security_class(tclass_name);
	if (!tclass)
		RETURN_FALSE;
	RETURN_LONG(tclass);
}

PHP_FUNCTION(selinux_class_to_string)
{
	long tclass;
	const char *tclass_name;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
				  &tclass) == FAILURE)
		RETURN_FALSE;

	tclass_name = security_class_to_string(tclass);
	if (!tclass_name)
		RETURN_FALSE;
	RETURN_STRING((char *)tclass_name, 1);
}

PHP_FUNCTION(selinux_string_to_av_perm)
{
	long tclass;
	char *av_perm_name;
	int length;
	access_vector_t av_perm;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls",
				  &tclass, &av_perm_name, &length) == FAILURE)
		RETURN_FALSE;
	av_perm = string_to_av_perm(tclass, av_perm_name);
	if (!av_perm)
		RETURN_FALSE;
	RETURN_LONG(av_perm);
}

PHP_FUNCTION(selinux_av_perm_to_string)
{
	long tclass, av_perm;
	const char *av_perm_name;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll",
				  &tclass, &av_perm) == FAILURE)
		RETURN_FALSE;

	av_perm_name = security_av_perm_to_string(tclass, av_perm);
	if (!av_perm_name)
		RETURN_FALSE;
	RETURN_STRING((char *)av_perm_name, 1);
}

PHP_FUNCTION(selinux_av_string)
{
	long tclass, av_perms;
	char *av_string;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll",
				  &tclass, &av_perms) == FAILURE)
		RETURN_FALSE;

	if (security_av_string(tclass, av_perms, &av_string) < 0)
		RETURN_FALSE;

	RETVAL_STRING(av_string, 1);
	free(av_string);
}

/*
 * mcstrans
 */
PHP_FUNCTION(selinux_trans_to_raw_context)
{
	security_context_t raw_context;
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (selinux_trans_to_raw_context(context, &raw_context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(raw_context, 1);
	freecon(raw_context);
}

PHP_FUNCTION(selinux_raw_to_trans_context)
{
	security_context_t trans_context;
	char *context;
	int length;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s", &context, &length) == FAILURE)
		RETURN_FALSE;

	if (selinux_raw_to_trans_context(context, &trans_context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(trans_context, 1);
	freecon(trans_context);
}

/*
 * matchpathcon
 */

static void do_selinux_matchpathcon(INTERNAL_FUNCTION_PARAMETERS, int raw)
{
	security_context_t context;
	char *path;
	int path_len;
	long mode = 0;
	zend_bool baseonly = 0;
	zend_bool validate = 0;
	unsigned int flags = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lbb",
				  &path, &path_len,
				  &mode, &baseonly, &validate) == FAILURE)
		RETURN_FALSE;

	if (baseonly)
		flags |= MATCHPATHCON_BASEONLY;
	if (raw)
		flags |= MATCHPATHCON_NOTRANS;
	if (validate)
		flags |= MATCHPATHCON_VALIDATE;

	set_matchpathcon_flags(flags);

	mode &= S_IFMT;
	if (matchpathcon(path, mode, &context) < 0)
		RETURN_FALSE;
	RETVAL_STRING(context, 1);
	freecon(context);
}

PHP_FUNCTION(selinux_matchpathcon)
{
	do_selinux_matchpathcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

PHP_FUNCTION(selinux_matchpathcon_raw)
{
	do_selinux_matchpathcon(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

PHP_FUNCTION(selinux_lsetfilecon_default)
{
	char *filename;
	int filename_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				  &filename, &filename_len) == FAILURE)
		RETURN_FALSE;

	if (selinux_lsetfilecon_default(filename) < 0)
		RETURN_FALSE;
	RETURN_TRUE;
}

#endif	/* HAVE_SELINUX */
