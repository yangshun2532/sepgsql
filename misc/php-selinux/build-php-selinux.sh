#!/bin/sh

export LANG=C

BASEDIR=`dirname "$0"` || exit 1
WKDIR=`mktemp -d` || exit 1

MAJOR_VERSION=1
MINOR_VERSION=`svn info ${BASEDIR}/selinux.c | grep ^Revision: | awk '{print $2}'`
VERSION="${MAJOR_VERSION}.${MINOR_VERSION}"
RELEASE="beta"

RPMSOURCE=`rpm -E '%_sourcedir'` || exit 1
TARBALL="php-selinux-${VERSION}"
WKDIR=`mktemp -d` || exit 1

svn export ${BASEDIR} ${WKDIR}/${TARBALL}

pushd ${WKDIR}
cat ${TARBALL}/php-selinux.spec			\
    | sed "s/%%__version__%%/${VERSION}/g"	\
    | sed "s/%%__release__%%/${RELEASE}/g"	\
    > ${RPMSOURCE}/php-selinux.spec
rm -f ${TARBALL}/`basename "$0"`
rm -f ${TARBALL}/php-selinux.spec
tar jc ${TARBALL} > ${RPMSOURCE}/${TARBALL}.tar.bz2

rpmbuild -ba ${RPMSOURCE}/php-selinux.spec

popd
rm -rf ${WKDIR}