RPMSOURCE=$(shell rpm -E %_sourcedir)
REVISION=$(shell env LANG=C svn info | grep ^Revision | awk '{print $$2}')

rpm: mod_selinux.c mod_selinux.te mod_selinux.conf mod_selinux.spec
	cp mod_selinux.c mod_selinux.te mod_selinux.conf $(RPMSOURCE)
	rpmbuild -ba mod_selinux.spec -D "mod_selinux_revision $(REVISION)"

clean:
	rm -rf .libs mod_selinux.la mod_selinux.lo mod_selinux.o mod_selinux.slo