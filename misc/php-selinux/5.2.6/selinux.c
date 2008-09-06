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
	PHP_FE(selinux_is_enabled,	NULL)
	PHP_FE(selinux_mls_is_enabled,	NULL)
	PHP_FE(selinux_getcon,		NULL)
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

PHP_FUNCTION(selinux_getcon)
{
	security_context_t context;

	if (getcon(&context) < 0)
		RETURN_FALSE;

	RETVAL_STRING(context, 1);
	freecon(context);
}

#endif	/* HAVE_SELINUX */
