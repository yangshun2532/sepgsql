#ifndef PHP_SELINUX_H
#define PHP_SELINUX_H

#ifdef HAVE_SELINUX

extern zend_module_entry selinux_module_entry;
#define selinux_module_ptr &selinux_module_entry

PHP_MINIT_FUNCTION(selinux);
PHP_FUNCTION(selinux_is_enabled);
PHP_FUNCTION(selinux_mls_is_enabled);
PHP_FUNCTION(selinux_getcon);

#else	/* HAVE_SELINUX */

#define selinux_module_ptr NULL

#endif	/* HAVE_SELINUX */

#define phpext_selinux_ptr selinux_module_ptr

#endif	/* PHP_SELINUX_H */
