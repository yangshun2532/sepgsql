#!/bin/sh

DEFAULT_REPOSITORY="http://sepgsql.googlecode.com/svn"

test -z "${SEPGSQL_REPOSITORY}" && SEPGSQL_REPOSITORY=${DEFAULT_REPOSITORY}

if [ -z "$1" ]; then
    echo "usage: $0 <selinux-policy.xxx.src.rpm>"
    exit 1
elif echo $1 | egrep -q "^(http|ftp)://"; then
    SRPMFILE=`mktemp`
    wget -O ${SRPMFILE} $1 || exit 1
else
    SRPMFILE=$1
fi

# unpack source rpm
SOURCE_DIR=`rpm -E '%{_sourcedir}'`
if [ ! -d ${SOURCE_DIR} ]; then
    echo "${SOURCE_DIR} is not a directory"
    exit 1
fi

cd ${SOURCE_DIR}
rm -f ${SOURCE_DIR}/*
rpm2cpio ${SRPMFILE} | cpio -id || exit 1
if [ ! -f selinux-policy.spec ]; then
    echo "selinux-policy.spec not found";
    exit 1
fi

# export repository
POLICY_REPO="`mktemp -d`/policy"
svn export "${SEPGSQL_REPOSITORY}/policy" ${POLICY_REPO}

# modify specfile
if rpm -qp --qf "%{release}" "${SRPMFILE}" | egrep -q '\.fc7$'; then
    # Fedora 7
    TEMPFILE=`mktemp`
    cp ${POLICY_REPO}/refpolicy-add-sepgsql-definitions.fedora7.patch ${SOURCE_DIR}
    cp ${POLICY_REPO}/refpolicy-add-userdomain-pgsql-connect.fedora7.patch ${SOURCE_DIR}
    cat selinux-policy.spec                                                                     \
        | sed 's/%{?dist}/.sepgsql%{?dist}/g'                                                   \
        | awk "BEGIN { a = b = 0; }                                                             \
               /^patch[0-9]*:/ { a++; print; next; }                                            \
               a > 0 { a = 0;                                                                   \
                       print \"patch98: refpolicy-add-sepgsql-definitions.fedora7.patch\";      \
                       print \"patch99: refpolicy-add-userdomain-pgsql-connect.fedora7.patch\"; \
                       print; next; }                                                           \
               /^%patch[0-9]*/ { b++; print; next; }                                            \
               b > 0 { b = 0;                                                                   \
                       print \"%patch98 -p1\";                                                  \
                       print \"%patch99 -p1\";                                                  \
                       print; next; }                                                           \
               { print; }" > $TEMPFILE
    cp $TEMPFILE selinux-policy.spec && rm -f $TEMPFILE
elif rpm -qp --qf "%{release}" "${SRPMFILE}" | egrep -q '\.fc8$'; then
    # Fedora 8 (rawhide)
    TEMPFILE=`mktemp`
    cp ${POLICY_REPO}/refpolicy-add-sepgsql-definitions.fedora8.patch ${SOURCE_DIR}
    cat selinux-policy.spec                                                                     \
        | sed 's/%{?dist}/.sepgsql%{?dist}/g'                                                   \
        | awk "BEGIN { a = b = 0; }                                                             \
               /^patch[0-9]*:/ { a++; print; next; }                                            \
               a > 0 { a = 0;                                                                   \
                       print \"patch99: refpolicy-add-sepgsql-definitions.fedora8.patch\";      \
                       print; next; }                                                           \
               /^%patch[0-9]*/ { b++; print; next; }                                            \
               b > 0 { b = 0;                                                                   \
                       print \"%patch99 -p1\";                                                  \
                       print; next; }                                                           \
               { print; }" > $TEMPFILE
    cp $TEMPFILE selinux-policy.spec && rm -f $TEMPFILE
else
    echo "unknown distribution: ${SRPMFILE}"
    exit 1
fi

# rpmbuild 
rpmbuild -ba ${SOURCE_DIR}/selinux-policy.spec
