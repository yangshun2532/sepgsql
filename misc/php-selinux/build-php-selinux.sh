#!/bin/sh

export LANG=C

BASEDIR=`dirname "$0"` || exit 1
RPMSOURCE=`rpm -E '%_sourcedir'` || exit 1
VERSION=`rpm -q --specfile  --queryformat '%{version}\n' ${BASEDIR}/php-selinux.spec | head -1`
REVISION=`svn info | grep ^Revision: | awk '{print $2}'`
TARBALL="php-selinux-${VERSION}"
WKDIR=`mktemp -d` || exit 1

svn export ${BASEDIR} ${WKDIR}/${TARBALL}

cd ${WKDIR}
cat ${TARBALL}/php-selinux.spec \
    | sed "s/%%__revision__%%/${REVISION}/g" \
    > ${RPMSOURCE}/php-selinux.spec
rm -f ${TARBALL}/`basename "$0"`
rm -f ${TARBALL}/php-selinux.spec
tar jc ${TARBALL} > ${RPMSOURCE}/${TARBALL}.tar.bz2

rpmbuild -ba ${RPMSOURCE}/php-selinux.spec
