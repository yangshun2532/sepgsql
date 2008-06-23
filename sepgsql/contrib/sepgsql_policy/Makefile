#
# contrib/sepgsql_policy/Makefile
#   Makefile of security policy module for SE-PostgreSQL
#
top_builddir = ../..
include $(top_builddir)/src/Makefile.global

policy_basedir	:= /usr/share/selinux
policy_makefile	:= $(policy_basedir)/devel/Makefile
policy_types	:= targeted mls
policy		:= $(strip $(shell $(AWK) -F= '/^SELINUXTYPE/{ print $$2 }' /etc/selinux/config))
package_names	:= sepostgresql sepostgresql-devel
prefix_ptn	:= "s/%%__prefix__%%/$(shell echo $(prefix)|sed 's/\//\\\//g')/g"
bindir_ptn	:= "s/%%__bindir__%%/$(shell echo $(bindir)|sed 's/\//\\\//g')/g"
libdir_ptn	:= "s/%%__libdir__%%/$(shell echo $(pkglibdir)|sed 's/\//\\\//g')/g"

all:
	$(foreach pkg, $(package_names), $(foreach p, $(policy_types), $(MAKE) $(MAKEOVERRIDES) policy=$(p) $(pkg).pp;))
	$(foreach pkg, $(package_names), test -e $(pkg).pp.$(policy) && ln -sf $(pkg).pp.$(policy) $(pkg).pp;)

.install-policy:
	test -d $(DESTDIR)$(policy_basedir)/$(policy) || install -d $(DESTDIR)$(policy_basedir)/$(policy)
	$(foreach pkg, $(package_names), install -p -m 644 $(pkg).pp.$(policy) $(DESTDIR)$(policy_basedir)/$(policy)/$(pkg).pp;)

install: all
	$(foreach p, $(policy_types), $(MAKE) $(MAKEOVERRIDES) policy=$(p) .install-policy;)

%.pp: %.te %.if %.fc
	rm -f $@
	$(MAKE) NAME=$(policy) -f $(policy_makefile) $@
	mv $@ $@.$(policy)

%.fc: sepostgresql.fc.template
	cat $< | sed -e $(prefix_ptn) -e $(bindir_ptn) -e $(libdir_ptn) > $@

clean:
	$(MAKE) -f $(policy_makefile) clean
	rm -f *.pp.* *.fc
