#!/bin/sh

BASEDIR=`dirname "$0"` || exit 1
cd $BASEDIR

REVISION=`env LANG=C svn ./* | grep '^Last Changed Rev'	| awk '{print $4}' | sort | tail -1`
RPMSOURCE=`rpm -E %{_sourcedir}`

cp -f mod_selinux.c    ${RPMSOURCE}
cp -f mod_selinux.conf ${RPMSOURCE}
cp -f mod_selinux.te   ${RPMSOURCE}
cp -f mod_selinux.map  ${RPMSOURCE}
cat mod_selinux.spec | sed "s/%%__mod_selinux_revision__%%/${REVISION}/g" > ${RPMSOURCE}/mod_selinux.spec

rpmbuild -ba ${RPMSOURCE}/mod_selinux.spec
