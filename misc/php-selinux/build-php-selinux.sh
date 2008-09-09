#!/bin/sh

if [ ! -r "$1" ]; then
    echo "usage: $0 <php source rpm>"
    exit 1
fi

BASEDIR=`dirname "$0"` || exit 1
PHPVERSION=`rpm -qp --queryformat %{version} "$1"` || exit 1
# check dirname
svn info ${BASEDIR}/${PHPVERSION} >& /dev/null || exit 1

# make a patch
RPMSOURCE=`rpm -E '%_sourcedir'` || exit 1
WKDIR=`mktemp -d` || exit 1
mkdir -p ${WKDIR}/php-${PHPVERSION}/ext/selinux
mkdir -p ${WKDIR}/php-selinux-${PHPVERSION}/ext
svn export ${BASEDIR}/${PHPVERSION} \
    ${WKDIR}/php-selinux-${PHPVERSION}/ext/selinux
(cd ${WKDIR}; diff -rpNU3 php-${PHPVERSION} php-selinux-${PHPVERSION}) \
    > ${RPMSOURCE}/php-${PHPVERSION}-selinux.patch

# extract source rpm
rpm2cpio "$1" | (cd ${RPMSOURCE}; cpio -idu)

# setup awk source file
(
    echo '/^Release:/ {'
    echo '    printf("%s selinux.%s\n", $1, $2)'
    echo '    next'
    echo '}'
    echo '/^BuildRoot:/ {'
    echo '    print "# PHP/SELinux binding"'
    echo "    print \"Patch99: php-${PHPVERSION}-selinux.patch\""
    echo '    print ""'
    echo '    print'
    echo '    print "BuildRequires: libselinux-devel"'
    echo '    print "Requires: libselinux"'
    echo '}'
    echo '/^%setup -q$/ {'
    echo '    print'
    echo '    print "%patch99 -p1"'
    echo '    next'
    echo '}'
    echo '/^%configure/ {'
    echo '    print'
    echo '    print "        --enable-selinux \\"'
    echo '    next'
    echo '}'
    echo '{ print }'
) > $WKDIR/php-selinux.awk

cat ${RPMSOURCE}/php.spec               \
    | awk -f $WKDIR/php-selinux.awk     \
    > ${RPMSOURCE}/php-selinux.spec

rpmbuild -ba ${RPMSOURCE}/php-selinux.spec