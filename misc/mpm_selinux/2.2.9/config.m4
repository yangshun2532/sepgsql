if test "$MPM_NAME" = "selinux" ; then
    APACHE_FAST_OUTPUT(server/mpm/$MPM_NAME/Makefile)

    AC_CHECK_LIB(selinux, is_selinux_enabled, [
        APR_ADDTO(AP_LIBS, [-lselinux])
    ])

    MODLIST="$MODLIST auth_selinux"
fi
