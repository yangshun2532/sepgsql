#ifndef PHP_SELINUX_H
#define PHP_SELINUX_H

#ifdef HAVE_SELINUX

extern zend_module_entry selinux_module_entry;
#define selinux_module_ptr &selinux_module_entry

PHP_MINIT_FUNCTION(selinux);
PHP_FUNCTION(selinux_is_enabled);
PHP_FUNCTION(selinux_mls_is_enabled);
PHP_FUNCTION(selinux_getcon);
PHP_FUNCTION(selinux_getcon_raw);
PHP_FUNCTION(selinux_setcon);
PHP_FUNCTION(selinux_setcon_raw);
PHP_FUNCTION(selinux_getpidcon);
PHP_FUNCTION(selinux_getpidcon_raw);
PHP_FUNCTION(selinux_getprevcon);
PHP_FUNCTION(selinux_getprevcon_raw);
PHP_FUNCTION(selinux_getexeccon);
PHP_FUNCTION(selinux_getexeccon_raw);
PHP_FUNCTION(selinux_setexeccon);
PHP_FUNCTION(selinux_setexeccon_raw);
PHP_FUNCTION(selinux_getfscreatecon);
PHP_FUNCTION(selinux_getfscreatecon_raw);
PHP_FUNCTION(selinux_setfscreatecon);
PHP_FUNCTION(selinux_setfscreatecon_raw);
PHP_FUNCTION(selinux_getkeycreatecon);
PHP_FUNCTION(selinux_getkeycreatecon_raw);
PHP_FUNCTION(selinux_setkeycreatecon);
PHP_FUNCTION(selinux_setkeycreatecon_raw);
PHP_FUNCTION(selinux_getsockcreatecon);
PHP_FUNCTION(selinux_getsockcreatecon_raw);
PHP_FUNCTION(selinux_setsockcreatecon);
PHP_FUNCTION(selinux_setsockcreatecon_raw);

/*
 * Get file context
 */
PHP_FUNCTION(selinux_getfilecon);
PHP_FUNCTION(selinux_getfilecon_raw);
PHP_FUNCTION(selinux_lgetfilecon);
PHP_FUNCTION(selinux_lgetfilecon_raw);
PHP_FUNCTION(selinux_fgetfilecon);
PHP_FUNCTION(selinux_fgetfilecon_raw);

/*
 * Set file context
 */
PHP_FUNCTION(selinux_setfilecon);
PHP_FUNCTION(selinux_setfilecon_raw);
PHP_FUNCTION(selinux_lsetfilecon);
PHP_FUNCTION(selinux_lsetfilecon_raw);
PHP_FUNCTION(selinux_fsetfilecon);
PHP_FUNCTION(selinux_fsetfilecon_raw);

/*
 * Labeled Networking
 */
PHP_FUNCTION(selinux_getpeercon);
PHP_FUNCTION(selinux_getpeercon_raw);

#else	/* HAVE_SELINUX */

#define selinux_module_ptr NULL

#endif	/* HAVE_SELINUX */

#define phpext_selinux_ptr selinux_module_ptr

#endif	/* PHP_SELINUX_H */
