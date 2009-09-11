#!/bin/sh

BASE_DIR=`(cd \`dirname $0\`/..; pwd)`
POLICY_DIR="${BASE_DIR}/misc/policy"
SRPMFILE="$1"

if [ -z "$SRPMFILE" ]; then
    echo "usage: $0 <selinux-policy.xxx.src.rpm>"
    exit 1
fi

if echo $SRPMFILE | egrep -q "^(http|ftp)://"; then
    TEMPFILE=`mktemp`
    wget -O "$TEMPFILE" "$SRPMFILE" || exit 1
    SRPMFILE="$TEMPFILE"
fi

PKG_NAME=`rpm -qp --queryformat='%{name}' $SRPMFILE`
PKG_VERSION=`rpm -qp --queryformat='%{version}' $SRPMFILE`

if [ "$PKG_NAME" != "selinux-policy" ]; then
    echo "$SRPMFILE is not selinux-policy package"
    exit 1
fi

# -- unpack source rpm
SOURCE_DIR=`rpm -E '%{_sourcedir}'`
test -d ${SOURCE_DIR} || mkdir -p ${SOURCE_DIR} || exit 1

BUILD_DIR=`rpm -E '%{_builddir}'`
test -d ${BUILD_DIR} || mkdir -p ${SOURCE_DIR} || exit 1

cd ${SOURCE_DIR}
rpm2cpio ${SRPMFILE} | cpio -idu || exit 1

rm -rf	${BUILD_DIR}/serefpolicy-${PKG_VERSION}.orig \
	${BUILD_DIR}/serefpolicy-${PKG_VERSION}.sepgsql

rpmbuild -bp selinux-policy.spec
mv  ${BUILD_DIR}/serefpolicy-${PKG_VERSION}	\
    ${BUILD_DIR}/serefpolicy-${PKG_VERSION}.orig

rpmbuild -bp selinux-policy.spec
mv  ${BUILD_DIR}/serefpolicy-${PKG_VERSION}	\
    ${BUILD_DIR}/serefpolicy-${PKG_VERSION}.sepgsql

cp  ${POLICY_DIR}/security_classes		\
    ${BUILD_DIR}/serefpolicy-${PKG_VERSION}.sepgsql/policy/flask
cp  ${POLICY_DIR}/access_vectors		\
    ${BUILD_DIR}/serefpolicy-${PKG_VERSION}.sepgsql/policy/flask
cp  ${POLICY_DIR}/mcs				\
    ${BUILD_DIR}/serefpolicy-${PKG_VERSION}.sepgsql/policy
cp  ${POLICY_DIR}/mls				\
    ${BUILD_DIR}/serefpolicy-${PKG_VERSION}.sepgsql/policy
cp  ${POLICY_DIR}/postgresql.*			\
    ${BUILD_DIR}/serefpolicy-${PKG_VERSION}.sepgsql/policy/modules/services

cd ${BUILD_DIR}
diff -rup serefpolicy-${PKG_VERSION}.orig serefpolicy-${PKG_VERSION}.sepgsql	\
    > ${SOURCE_DIR}/serefpolicy-sepgsql.patch

# -- modify specfile
TEMPFILE=`mktemp` || exit 1

cat ${SOURCE_DIR}/selinux-policy.spec	| \
    sed 's/%{?dist}/.sepgsql%{?dist}/g' | \
    awk	"BEGIN { a = b = 0; }
	 /^Source[0-9]+:/ && a == 0 { a = 1;
	  print \"patch99: serefpolicy-sepgsql.patch\";
	  print; next; }
	 /^%patch[0-9]*/ && b == 0 { b = 1;
	  print;
	  print \"%patch99 -p1\";
	  next; }
	{ print; next; }" > $TEMPFILE
cp $TEMPFILE ${SOURCE_DIR}/selinux-policy.spec

# rpmbuild 
rpmbuild -ba ${SOURCE_DIR}/selinux-policy.spec -D "BUILD_MLS 0" -D "BUILD_MINIMUM 0"
