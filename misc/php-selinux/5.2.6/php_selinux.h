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
PHP_FUNCTION(selinux_lsetfilecon_default);

/*
 * Labeled Networking
 */
PHP_FUNCTION(selinux_getpeercon);
PHP_FUNCTION(selinux_getpeercon_raw);

/*
 * security_compute_XXXX() wrappers
 */
PHP_FUNCTION(selinux_compute_av);
PHP_FUNCTION(selinux_compute_av_raw);
PHP_FUNCTION(selinux_compute_create);
PHP_FUNCTION(selinux_compute_create_raw);
PHP_FUNCTION(selinux_compute_relabel);
PHP_FUNCTION(selinux_compute_relabel_raw);
PHP_FUNCTION(selinux_compute_member);
PHP_FUNCTION(selinux_compute_member_raw);
PHP_FUNCTION(selinux_compute_user);
PHP_FUNCTION(selinux_compute_user_raw);

/*
 * get initial context
 */
PHP_FUNCTION(selinux_get_initial_context);
PHP_FUNCTION(selinux_get_initial_context_raw);

/*
 * sanity check in security context
 */
PHP_FUNCTION(selinux_check_context);
PHP_FUNCTION(selinux_check_context_raw);
PHP_FUNCTION(selinux_canonicalize_context);
PHP_FUNCTION(selinux_canonicalize_context_raw);

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
PHP_FUNCTION(selinux_matchpathcon_raw);

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
