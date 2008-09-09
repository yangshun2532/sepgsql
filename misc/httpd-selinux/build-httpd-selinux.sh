#!/bin/sh

if [ ! -r "$1" ]; then
    echo "usage: $0 <httpd source rpm>"
    exit 1
fi

BASEDIR=`dirname "$0"` || exit 1
VERSION=`rpm -qp --queryformat %{version} "$1"` || exit 1
# check dirname
svn info ${BASEDIR}/${VERSION} >& /dev/null || exit 1

# make a patch
RPMSOURCE=`rpm -E '%_sourcedir'` || exit 1
WKDIR=`mktemp -d` || exit 1
mkdir -p ${WKDIR}/httpd-${VERSION}/server/mpm/selinux
mkdir -p ${WKDIR}/httpd-selinux-${VERSION}/server/mpm
svn export ${BASEDIR}/${VERSION} \
    ${WKDIR}/httpd-selinux-${VERSION}/server/mpm/selinux
(cd ${WKDIR}; diff -rpNU3 httpd-${VERSION} httpd-selinux-${VERSION}) \
    > ${RPMSOURCE}/httpd-selinux.conf

# extract source rpm
rpm2cpio "$1" | (cd ${RPMSOURCE}; cpio -idu)

cp ${BASEDIR}/httpd-selinux.conf ${RPMSOURCE}

cat ${RPMSOURCE}/httpd.spec              \
    | awk -f ${BASEDIR}/httpd.spec.awk   \
    > ${RPMSOURCE}/httpd-selinux.spec

rpmbuild -ba ${RPMSOURCE}/httpd-selinux.spec

