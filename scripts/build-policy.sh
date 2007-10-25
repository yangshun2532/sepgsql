#!/bin/sh

# -- SE-PostgreSQL repository
SEPGSQL_REPOSITORY=`(cd \`dirname $0\`/..; pwd)`
SEPGSQL_BRANCH="/branches/pgsql-8.2.x"

if [ -z "$1" ]; then
    echo "usage: $0 <selinux-policy.xxx.src.rpm>"
    exit 1
fi

if echo $1 | egrep -q "^(http|ftp)://"; then
    SRPMFILE=`mktemp`
    wget -O ${SRPMFILE} $1 || exit 1
fi

# -- unpack source rpm
SOURCE_DIR=`rpm -E '%{_sourcedir}'`
test -d ${SOURCE_DIR} || exit 1

cd ${SOURCE_DIR}
rm -f `rpm -qpl ${SRPMFILE}`

rpm2cpio ${SRPMFILE} | cpio -id || exit 1
if [ ! -f selinux-policy.spec ]; then
    echo "selinux-policy.spec not found";
    exit 1
fi

# export repository
POLICY_REPO="`mktemp -d`/package"
svn export "${SEPGSQL_REPOSITORY}${SEPGSQL_BRANCH}/package" ${POLICY_REPO}

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
else
    echo "Only Fedora 7 need to add object class definitions"
    echo "In Fedora 8 or later, the upstreamed selinux-policy contains"
    echo "object class definitions."
    exit 1
fi

# rpmbuild 
rpmbuild -ba ${SOURCE_DIR}/selinux-policy.spec
