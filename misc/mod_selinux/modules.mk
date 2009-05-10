mod_selinux.la: mod_selinux.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version -lselinux mod_selinux.lo
mod_authn_sepgsql.la: mod_authn_sepgsql.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version -lpq mod_authn_sepgsql.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_selinux.la mod_authn_sepgsql.la
