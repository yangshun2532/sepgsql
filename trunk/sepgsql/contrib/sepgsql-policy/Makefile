# SE-PostgreSQL Security Policy
#------------------------------

SHAREDIR := /usr/share/selinux

AWK ?= gawk
NAME ?= $(strip $(shell $(AWK) -F= '/^SELINUXTYPE/{ print $$2 }' /etc/selinux/config))

SELINUX_POLICY := /usr/share/selinux

all: sepostgresql.pp

install: all
	install -m 0644 sepostgresql.pp $(SELINUX_POLICY)/$(NAME)

sepostgresql.pp: sepostgresql.te sepostgresql.if sepostgresql.fc
	make -f $(SELINUX_POLICY)/devel/Makefile NAME=$(NAME)

clean:
	make -f $(SELINUX_POLICY)/devel/Makefile NAME=$(NAME) clean
