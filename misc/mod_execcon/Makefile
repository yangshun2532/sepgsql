RPMSOURCE=$(shell rpm -E %_sourcedir)
REVISION=$(shell env LANG=C svn info | grep ^Revision | awk '{print $$2}')
POLICY_MKFILE=/usr/share/selinux/devel/Makefile

ifeq ($(POLICYRPM),)
	POLICY_VERSION=$(shell rpm -q --queryformat='%{version}' -f $(POLICY_MKFILE))
	POLICY_PKGNAME=$(shell rpm -q --queryformat='%{name}' -f $(POLICY_MKFILE))
	POLICY_BASEDIR=/
else
	POLICY_VERSION=$(shell rpm -q --queryformat='%{version}' -p $(POLICYRPM))
	POLICY_PKGNAME=$(shell rpm -q --queryformat='%{name}' -p $(POLICYRPM))
	POLICY_BASEDIR=$(shell TEMP=`mktemp -d`; rpm2cpio $(POLICYRPM) | (cd $$TEMP; cpio -idu); echo $$TEMP)
endif

rpm: $(POLICY_BASEDIR)/$(POLICY_MKFILE) mod_selinux.c mod_selinux.te mod_selinux.conf mod_selinux.spec
	cp mod_selinux.c mod_selinux.te mod_selinux.conf $(RPMSOURCE)
	cat mod_selinux.spec | sed -e 's/%%__selinux_policy_name__%%/$(POLICY_PKGNAME)/g' -e 's/%%__selinux_policy_version__%%/$(POLICY_VERSION)/g' > $(RPMSOURCE)/mod_selinux.spec
	rpmbuild -ba $(RPMSOURCE)/mod_selinux.spec -D "mod_selinux_revision $(REVISION)"

clean:
	rm -rf .libs mod_selinux.la mod_selinux.lo mod_selinux.o mod_selinux.slo

