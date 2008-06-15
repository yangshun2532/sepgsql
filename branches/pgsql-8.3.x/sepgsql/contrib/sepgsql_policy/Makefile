#
# contrib/sepgsql_policy/Makefile
#   Makefile of security policy module for SE-PostgreSQL
#
top_builddir = ../..
include $(top_builddir)/src/Makefile.global

policy_type	:= $(strip $(shell $(AWK) -F= '/^SELINUXTYPE/{ print $$2 }' /etc/selinux/config))
prefix_ptn	:= "s/%%__prefix__%%/$(shell echo $(prefix)|sed 's/\//\\\//g')/g"
bindir_ptn	:= "s/%%__bindir__%%/$(shell echo $(bindir)|sed 's/\//\\\//g')/g"
libdir_ptn	:= "s/%%__libdir__%%/$(shell echo $(pkglibdir)|sed 's/\//\\\//g')/g"

all:	sepostgresql.pp.targeted sepostgresql.pp.mls
	ln -sf sepostgresql.pp.$(policy_type) sepostgresql.pp

sepostgresql.pp.targeted: sepostgresql.te sepostgresql.if sepostgresql.fc
	rm -f sepostgresql.pp
	make NAME=targeted -f /usr/share/selinux/devel/Makefile
	mv sepostgresql.pp sepostgresql.pp.targeted

sepostgresql.pp.mls: sepostgresql.te sepostgresql.if sepostgresql.fc
	rm -f sepostgresql.pp
	make NAME=mls -f /usr/share/selinux/devel/Makefile
	mv sepostgresql.pp sepostgresql.pp.mls

sepostgresql.fc: sepostgresql.fc.template
	cat sepostgresql.fc.template | sed -e $(prefix_ptn) -e $(bindir_ptn) -e $(libdir_ptn) > sepostgresql.fc

clean:
	rm -rf sepostgresql.fc sepostgresql.pp* tmp