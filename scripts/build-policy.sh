#!/bin/sh

BASE_DIR=`(cd \`dirname $0\`/..; pwd)`
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

# -- unpack source rpm
SOURCE_DIR=`rpm -E '%{_sourcedir}'`
test -d ${SOURCE_DIR} || exit 1

cd ${SOURCE_DIR}
rm -f `rpm -qpl ${SRPMFILE}`

rpm2cpio ${SRPMFILE} | cpio -id || exit 1
cp ${BASE_DIR}/scripts/serefpolicy-sepgsql.patch ./
if [ ! -f selinux-policy.spec ]; then
    echo "selinux-policy.spec not found";
    exit 1
fi

# -- modify specfile
TEMPFILE=`mktemp` || exit 1

cat selinux-policy.spec \
    | awk      "BEGIN { a = b = 0 }					\
		/^Source[0-9]+:/ && a == 0			       	\
		{ a = 1;						\
		  print \"patch99: serefpolicy-sepgsql.patch\";		\
		  print; next; }					\
		/%patch[0-9]*/ && b == 0				\
		{ b = 1;						\
		  print;						\
		  print \"%patch99 -p1\";				\
		  next;							\
		}							\
		/^%clean/						\
		{							\
		  print \"%if %{BUILD_TARGETED}\";			\
		  print \"install -m 644 %{buildroot}%{_usr}/share/selinux/targeted/base.pp.bz2 \\\\\";	\
		  print \"    %{buildroot}%{_usr}/share/selinux/packages/base-sepgsql.targeted.pp.bz2\";\
		  print \"%endif\";					\
		  print \"%if %{BUILD_MLS}\";				\
		  print \"install -m 644 %{buildroot}%{_usr}/share/selinux/mls/base.pp.bz2 \\\\\";	\
		  print \"    %{buildroot}%{_usr}/share/selinux/packages/base-sepgsql.mls.pp.bz2\";	\
		  print \"%endif\";					\
		  print \"%if %{BUILD_MINIMUM}\";			\
		  print \"install -m 644 %{buildroot}%{_usr}/share/selinux/minimum/base.pp.bz2 \\\\\";	\
		  print	\"    %{buildroot}%{_usr}/share/selinux/packages/base-sepgsql.minimum.pp.bz2\";	\
		  print \"%endif\";					\
		  print \"\";						\
		  print; next;						\
		}							\
		/^%changelog/						\
		{							\
		  print \"%package sepgsql\";				\
		  print \"Summary: SELinux experimental database policy\";		\
		  print \"Group: System Environment/Base\";		\
		  print \"Requires(pre): selinux-policy = %{version}-%{release}\";	\
		  print \"\";						\
		  print \"%description sepgsql\";			\
		  print \"SELinux experimental database policy\";	\
		  print \"\";						\
		  print \"%files sepgsql\";				\
		  print \"%{_usr}/selinux/packages/base-sepgsql.*.pp.bz2\";	\
		  print \"\";						\
		  print; next;						\
		}							\
		{							\
		  print;						\
		}" > $TEMPFILE
cp $TEMPFILE selinux-policy.spec

# rpmbuild 
rpmbuild -ba ${SOURCE_DIR}/selinux-policy.spec	\
	-D "BUILD_MINIMUM 0" -D "BUILD_OLPC 0" -D "BUILD_MLS 1"
