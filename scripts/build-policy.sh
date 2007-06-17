#!/bin/sh

DEFAULT_REPOSITORY="http://sepgsql.googlecode.com/svn"
POLICY_98="refpolicy-add-sepgsql-definitions.patch"
POLICY_99="refpolicy-add-userdomain-pgsql-connect.patch"

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
test -d ${SOURCE_DIR} || { echo "${SOURCE_DIR} not a directory"; exit 1; }
cd ${SOURCE_DIR}
rm ${SOURCE_DIR}/*
rpm2cpio ${SRPMFILE} | cpio -id || exit 1
test -f ${SOURCE_DIR}/selinux-policy.spec || \
    { echo "selinux-policy.spec not found"; exit 1; }

# fetch patches from repository
TEMPDIR=`mktemp -d`
svn export "${SEPGSQL_REPOSITORY}/policy" ${TEMPDIR}/policy
set | grep ^POLICY_ | 


PATCH_DEF=""
PATCH_APPLY=""
LIST=`set | grep ^POLICY_ | sed 's/POLICY_//g'`
for x in $LIST
do
    PATCH_NO=`echo $x | sed 's/=/ /g' | awk '{ print $1 }'`
    PATCH_FILE=`echo $x | sed 's/=/ /g' | awk '{ print $2 }'`
    echo $PATCH_NO | egrep -q '^[0-9]+$' || \
        { echo "${PATCH_NO} not a numerical value"; exit 1; }
    test -f ${TEMPDIR}/policy/${PATCH_FILE} || \
        { echo "${PATCH_FILE} not found"; exit 1; }

    cp ${TEMPDIR}/policy/${PATCH_FILE} ${SOURCE_DIR}
    PATCH_DEF="${PATCH_DEF} print(\"patch${PATCH_NO}: ${PATCH_FILE}\");"
    PATCH_APPLY="${PATCH_APPLY} print(\"%patch${PATCH_NO} -p1\");"
done
rm -rf ${TEMPDIR}

# modify spec file
_SPEC=`mktemp`
cat ${SOURCE_DIR}/selinux-policy.spec                   \
    sed 's/%{?dist}/.sepgsql%{?dist}/g'                 \
    | awk "BEGIN { a = b = 0; }                         \
           /^patch[0-9]*:/ { a++; print; next; }        \
           a > 0 { a=0; ${PATCH_DEF}; print; next; }    \
           /^%patch[0-9]*/ { b++; print; next; }        \
           b > 0 { b=0; ${PATCH_APPLY}; print; next; }  \
           { print }" > ${_SPEC}
cp ${_SPEC} ${SOURCE_DIR}/selinux-policy.spec
rm -f ${_SPEC}

# rpmbuild 
rpmbuild -ba ${SOURCE_DIR}/selinux-policy.spec