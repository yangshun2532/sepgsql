#
# Makefile for SE-PostgreSQL security policy module
#
top_builddir = ../../../../..
include $(top_builddir)/src/Makefile.global

POLICY_BASEDIR	:= $(DESTDIR)/usr/share/selinux
POLICY_MAKEFILE	:= $(POLICY_BASEDIR)/devel/Makefile
POLICY_INSTDIR  := $(POLICY_BASEDIR)/packages
PREFIX_RULE	:= "s/%%__prefix__%%/$(shell echo $(prefix)|sed 's/\//\\\//g')/g"
BINDIR_RULE	:= "s/%%__bindir__%%/$(shell echo $(bindir)|sed 's/\//\\\//g')/g"
LIBDIR_RULE	:= "s/%%__libdir__%%/$(shell echo $(pkglibdir)|sed 's/\//\\\//g')/g"

all: sepostgresql-devel.pp

install: all
	test -d $(POLICY_INSTDIR) || mkdir -p $(POLICY_INSTDIR)
	install -p -m 0644 sepostgresql-devel.pp $(POLICY_INSTDIR)

sepostgresql-devel.pp: sepostgresql-devel.te sepostgresql-devel.fc
	$(MAKE) -f $(POLICY_MAKEFILE)

sepostgresql-devel.fc: sepostgresql-devel.fc.template
	cat $< | sed -e $(PREFIX_RULE) -e $(BINDIR_RULE) -e $(LIBDIR_RULE) > $@

clean:
	$(MAKE) -f $(POLICY_MAKEFILE) clean
	rm -f *.fc
