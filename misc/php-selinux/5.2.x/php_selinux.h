#ifndef PHP_SELINUX_H
#define PHP_SELINUX_H

#ifdef HAVE_SELINUX

extern zend_module_entry selinux_module_entry;
#define selinux_module_ptr &selinux_module_entry

PHP_RSHUTDOWN_FUNCTION(selinux);

/*
 * Global state API
 */
PHP_FUNCTION(selinux_is_enabled);
PHP_FUNCTION(selinux_mls_is_enabled);
PHP_FUNCTION(selinux_getenforce);
PHP_FUNCTION(selinux_setenforce);
PHP_FUNCTION(selinux_policyvers);

/*
 * Wrappers for the /proc/<pid>/attr API
 */
PHP_FUNCTION(selinux_getcon);
PHP_FUNCTION(selinux_setcon);
PHP_FUNCTION(selinux_getpidcon);
PHP_FUNCTION(selinux_getprevcon);
PHP_FUNCTION(selinux_getexeccon);
PHP_FUNCTION(selinux_setexeccon);
PHP_FUNCTION(selinux_getfscreatecon);
PHP_FUNCTION(selinux_setfscreatecon);
PHP_FUNCTION(selinux_getkeycreatecon);
PHP_FUNCTION(selinux_setkeycreatecon);
PHP_FUNCTION(selinux_getsockcreatecon);
PHP_FUNCTION(selinux_setsockcreatecon);

/*
 * Get file context
 */
PHP_FUNCTION(selinux_getfilecon);
PHP_FUNCTION(selinux_lgetfilecon);
PHP_FUNCTION(selinux_fgetfilecon);

/*
 * Set file context
 */
PHP_FUNCTION(selinux_setfilecon);
PHP_FUNCTION(selinux_lsetfilecon);
PHP_FUNCTION(selinux_fsetfilecon);
PHP_FUNCTION(selinux_lsetfilecon_default);

/*
 * Labeled Networking
 */
PHP_FUNCTION(selinux_getpeercon);

/*
 * security_compute_XXXX() wrappers
 */
PHP_FUNCTION(selinux_compute_av);
PHP_FUNCTION(selinux_compute_create);
PHP_FUNCTION(selinux_compute_relabel);
PHP_FUNCTION(selinux_compute_member);
PHP_FUNCTION(selinux_compute_user);

/*
 * get initial context
 */
PHP_FUNCTION(selinux_get_initial_context);

/*
 * sanity check in security context
 */
PHP_FUNCTION(selinux_check_context);
PHP_FUNCTION(selinux_canonicalize_context);

/*
 * booleans
 */
PHP_FUNCTION(selinux_get_boolean_names);
PHP_FUNCTION(selinux_get_boolean_pending);
PHP_FUNCTION(selinux_get_boolean_active);
PHP_FUNCTION(selinux_set_boolean);
PHP_FUNCTION(selinux_commit_booleans);

/*
 * security class/access vector mapping
 */
PHP_FUNCTION(selinux_string_to_class);
PHP_FUNCTION(selinux_class_to_string);
PHP_FUNCTION(selinux_av_perm_to_string);
PHP_FUNCTION(selinux_string_to_av_perm);
PHP_FUNCTION(selinux_av_string);

/*
 * mcstrans
 */
PHP_FUNCTION(selinux_trans_to_raw_context);
PHP_FUNCTION(selinux_raw_to_trans_context);

/*
 * matchpathcon
 */
PHP_FUNCTION(selinux_matchpathcon);

/*
 * configuration files
 */
PHP_FUNCTION(selinux_getenforcemode);
PHP_FUNCTION(selinux_getpolicytype);
PHP_FUNCTION(selinux_policy_root);

#else	/* HAVE_SELINUX */

#define selinux_module_ptr NULL

#endif	/* HAVE_SELINUX */

#define phpext_selinux_ptr selinux_module_ptr

#endif	/* PHP_SELINUX_H */