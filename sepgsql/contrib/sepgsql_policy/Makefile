#
# contrib/sepgsql_policy/Makefile
#   Makefile of security policy module for SE-PostgreSQL
#
top_builddir = ../..
include $(top_builddir)/src/Makefile.global

policy_types	:= targeted mls
policy		:= $(strip $(shell $(AWK) -F= '/^SELINUXTYPE/{ print $$2 }' /etc/selinux/config))
prefix_ptn	:= "s/%%__prefix__%%/$(shell echo $(prefix)|sed 's/\//\\\//g')/g"
bindir_ptn	:= "s/%%__bindir__%%/$(shell echo $(bindir)|sed 's/\//\\\//g')/g"
libdir_ptn	:= "s/%%__libdir__%%/$(shell echo $(pkglibdir)|sed 's/\//\\\//g')/g"


all:
	for X in $(policy_types); do $(MAKE) $(MAKEOVERRIDES) policy=$$X sepostgresql.pp; done
	test -e sepostgresql.pp.$(policy) && ln -sf sepostgresql.pp.$(policy) sepostgresql.pp

.install-policy:
	test -d $(DESTDIR)/usr/share/selinux/$(policy) || install -d $(DESTDIR)/usr/share/selinux/$(policy)
	install -p -m 644 sepostgresql.pp.$(policy) $(DESTDIR)/usr/share/selinux/$(policy)/sepostgresql.pp

install: all
	for X in $(policy_types); do $(MAKE) $(MAKEOVERRIDES) policy=$$X .install-policy; done

sepostgresql.pp: sepostgresql.te sepostgresql.if sepostgresql.fc
	$(MAKE) NAME=$(policy) -f /usr/share/selinux/devel/Makefile
	mv sepostgresql.pp sepostgresql.pp.$(policy)

sepostgresql.fc: sepostgresql.fc.template
	cat sepostgresql.fc.template | sed -e $(prefix_ptn) -e $(bindir_ptn) -e $(libdir_ptn) > sepostgresql.fc

clean:
	rm -rf sepostgresql.fc sepostgresql.pp* tmp