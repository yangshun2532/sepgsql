#!/bin/sh

REPO=`cd \`dirname $0\`/..; pwd`
SRCDIR=`rpm -E %_sourcedir`
test -d ${SRCDIR} || exit 1

if [ ! -r "$1" ]; then
    echo "usage: `basename $0` <httpd source rpm file>"
    exit 1
fi
VERSION=`rpm -qp --queryformat %{version} $1` || exit 1

rpm2cpio $1 | (cd $SRCDIR; cpio -idu) || exit 1

mv $SRCDIR/httpd.spec $SRCDIR/httpd.spec.orig || exit 1

awk -f ${REPO}/misc/mpm_selinux/httpd.spec.awk > $SRCDIR/httpd.spec < $SRCDIR/httpd.spec.orig

#--- make patches ---
WKDIR=`mktemp -d` || exit 1
cd $WKDIR
tar zxf $SRCDIR/httpd-${VERSION}.tar.gz; mv httpd-${VERSION} httpd-${VERSION}.orig
tar zxf $SRCDIR/httpd-${VERSION}.tar.gz; mv httpd-${VERSION} httpd-${VERSION}.selinux
svn export ${REPO}/misc/mpm_selinux/${VERSION} \
    httpd-${VERSION}.selinux/server/mpm/selinux || exit 1
svn export ${REPO}/misc/mpm_selinux/policy \
    httpd-${VERSION}.selinux/server/mpm/selinux/policy || exit 1
diff -prNU3 httpd-${VERSION}.orig/server/mpm httpd-${VERSION}.selinux/server/mpm > ${SRCDIR}/httpd-mpm-selinux.patch

cp ${REPO}/misc/mpm_selinux/mpm_selinux.conf ${SRCDIR}

rpmbuild -ba ${SRCDIR}/httpd.spec
