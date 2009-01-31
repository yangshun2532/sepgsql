#
# Makefile for SE-PostgreSQL security policy module
#
top_builddir = ../../../../..
include $(top_builddir)/src/Makefile.global

POLICY_BASEDIR	:= $(DESTDIR)/usr/share/selinux
POLICY_MAKEFILE	:= $(POLICY_BASEDIR)/devel/Makefile
POLICY_TYPES	:= targeted mls
POLICY_TARGET	:= $(strip $(shell $(AWK) -F= '/^SELINUXTYPE/{ print $$2 }' /etc/selinux/config))
PREFIX_RULE	:= "s/%%__prefix__%%/$(shell echo $(prefix)|sed 's/\//\\\//g')/g"
BINDIR_RULE	:= "s/%%__bindir__%%/$(shell echo $(bindir)|sed 's/\//\\\//g')/g"
LIBDIR_RULE	:= "s/%%__libdir__%%/$(shell echo $(pkglibdir)|sed 's/\//\\\//g')/g"

all: $(addprefix sepostgresql-devel.pp., $(POLICY_TYPES))
	ln -s sepostgresql-devel.pp.$(POLICY_TARGET) sepostgresql-devel.pp

sepostgresql-devel.pp.%: sepostgresql-devel.te sepostgresql-devel.fc	
	$(MAKE) NAME=$(POLICY_TARGET) -f $(POLICY_MAKEFILE) clean
	$(MAKE) NAME=$(POLICY_TARGET) -f $(POLICY_MAKEFILE)
	mv $(basename $@) $@

sepostgresql-devel.fc: sepostgresql-devel.fc.template
	cat $< | sed -e $(PREFIX_RULE) -e $(BINDIR_RULE) -e $(LIBDIR_RULE) > $@

clean:
	$(MAKE) -f $(POLICY_MAKEFILE) clean
	rm -f *.pp *.pp.* *.fc
