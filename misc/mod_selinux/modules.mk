mod_selinux.la: mod_selinux.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version -lselinux mod_selinux.so
DISTCLEAN_TARGETS = modules.mk
shared =  mod_selinux.la
