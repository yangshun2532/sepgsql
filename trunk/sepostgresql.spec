#
# Security Enhanced PostgreSQL (SE-PostgreSQL)
#
# Copyright 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
# -----------------------------------------------------

%define _prefix	/opt/sepgsql
%define _mandir %{_prefix}/man
%define beta	a
%{!?sepgversion:%define sepgversion 1}
%{!?sepgrevision:%define sepgrevision 0}

Summary: Security Enhanced PostgreSQL
Group: Applications/Databases
Name: sepostgresql
Version: 8.2.3
Release: %{sepgversion}.%{sepgrevision}%{beta}
License: BSD
Group: Applications/Databases
Url: http://code.google.com/p/sepgsql/
Buildroot: %{_tmppath}/%{name}-%{version}-root
Source0: postgresql-%{version}.tar.gz
Source1: sepostgresql.init
Source2: sepostgresql.if
Source3: sepostgresql.te
Source4: sepostgresql.fc
Patch0: sepostgresql-%{version}-%{sepgrevision}.patch

Buildrequires: autoconf libselinux-devel selinux-policy-devel

%description
Security Enhanced PostgreSQL is an extension of PostgreSQL
based on SELinux security policy, that applies fine grained
mandatory access control to many objects within the database,
and takes advantage of user authorization integrated within
the operating system. SE-PostgreSQL works as a userspace
reference monitor to check any SQL query.

%prep
%setup -q -n postgresql-%{version}
%patch0 -p1

%build
# build Binary Policy Module
mkdir -p policy
pushd policy
cp %{SOURCE2} %{SOURCE3} %{SOURCE4} .
make -f /usr/share/selinux/devel/Makefile
popd

# build SE-PostgreSQL
autoconf
%configure	--enable-selinux \
		--host=%{_host} --build=%{_build} \
%if %{defined beta}
		--enable-debug \
		--enable-cassert \
%endif
		--prefix=%{_prefix}
# parallel build, if possible
NCPUS=`grep -c ^processor /proc/cpuinfo`
make -j ${NCPUS}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT/altroot install
ALTROOT="$RPM_BUILD_ROOT/altroot"
install -d -m 755 $RPM_BUILD_ROOT%{_bindir}
mv	${ALTROOT}%{_bindir}/initdb			\
	${ALTROOT}%{_bindir}/ipcclean			\
	${ALTROOT}%{_bindir}/pg_controldata		\
	${ALTROOT}%{_bindir}/pg_ctl			\
	${ALTROOT}%{_bindir}/pg_resetxlog		\
	${ALTROOT}%{_bindir}/postgres			\
	${ALTROOT}%{_bindir}/postmaster			\
	$RPM_BUILD_ROOT%{_bindir}
install -d -m 755 $RPM_BUILD_ROOT%{_mandir}/man1
mv	${ALTROOT}%{_mandir}/man1/initdb.*		\
	${ALTROOT}%{_mandir}/man1/ipcclean.*		\
	${ALTROOT}%{_mandir}/man1/pg_controldata.*	\
	${ALTROOT}%{_mandir}/man1/pg_ctl.*		\
	${ALTROOT}%{_mandir}/man1/pg_resetxlog.*	\
	${ALTROOT}%{_mandir}/man1/postgres.*		\
	${ALTROOT}%{_mandir}/man1/postmaster.*		\
	$RPM_BUILD_ROOT%{_mandir}/man1
install -d -m 755 $RPM_BUILD_ROOT%{_datadir}
mv	${ALTROOT}%{_datadir}/postgres.bki		\
	${ALTROOT}%{_datadir}/postgres.description	\
	${ALTROOT}%{_datadir}/postgres.shdescription	\
	${ALTROOT}%{_datadir}/system_views.sql		\
	${ALTROOT}%{_datadir}/*.sample			\
	${ALTROOT}%{_datadir}/timezone/			\
	${ALTROOT}%{_datadir}/timezonesets/		\
	${ALTROOT}%{_datadir}/conversion_create.sql	\
	${ALTROOT}%{_datadir}/information_schema.sql	\
	${ALTROOT}%{_datadir}/sql_features.txt		\
	$RPM_BUILD_ROOT%{_datadir}
install -d -m 755 $RPM_BUILD_ROOT%{_libdir}
mv	${ALTROOT}%{_libdir}/plpgsql.so			\
	${ALTROOT}%{_libdir}/libpq.*			\
	${ALTROOT}%{_libdir}/libpgtypes.*		\
	${ALTROOT}%{_libdir}/*_and_*.so			\
	$RPM_BUILD_ROOT%{_libdir}

test -e policy/sepostgresql.pp || exit 1
install -m 644 policy/sepostgresql.pp $RPM_BUILD_ROOT/%{_datadir}

install -d -m 700 $RPM_BUILD_ROOT/var/lib/sepgsql
install -d -m 700 $RPM_BUILD_ROOT/var/lib/sepgsql/data
install -d -m 700 $RPM_BUILD_ROOT/var/lib/sepgsql/backups

mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m 755 %{SOURCE1} $RPM_BUILD_ROOT/etc/rc.d/init.d/sepostgresql

(echo "[ -f /etc/profile ] && source /etc/profile"
 echo 
 echo "PGDATA=/var/lib/sepgsql/data"
 echo "export PGDATA") > $RPM_BUILD_ROOT/var/lib/sepgsql/.bash_profile
rm -rf $ALTROOT

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ $1 -eq 1 ]; then	# rpm -i cases
	groupadd -r sepgsql >& /dev/null || :
	useradd -g sepgsql -d /var/lib/sepgsql -s /bin/bash \
		-r -c "SE-PostgreSQL server" sepgsql >& /dev/null || :
	semodule -i %{_datadir}/sepostgresql.pp || :
fi

%post
chkconfig --add sepostgresql
/sbin/ldconfig

%postun
/sbin/ldconfig
if [ $1 -eq 0 ]; then	# rpm -e cases
	userdel  sepgsql >& /dev/null || :
	groupdel sepgsql >& /dev/null || :
	semodule -r sepostgresql
elif [ $1 -gq 1 ]; then	# rpm -Uvh cases
	/sbin/service sepostgresql condrestart >/dev/null 2>&1 || :
	semodule -u %{_datadir}/sepostgresql.pp || :
fi

%files
%defattr(-,root,root,-)
/etc/rc.d/init.d/sepostgresql
%dir %{_bindir}
%{_bindir}/initdb
%{_bindir}/ipcclean
%{_bindir}/pg_controldata
%{_bindir}/pg_ctl
%{_bindir}/pg_resetxlog
%{_bindir}/postgres
%{_bindir}/postmaster
%dir %{_mandir}
%dir %{_mandir}/man1
%{_mandir}/man1/initdb.*
%{_mandir}/man1/ipcclean.*
%{_mandir}/man1/pg_controldata.*
%{_mandir}/man1/pg_ctl.*
%{_mandir}/man1/pg_resetxlog.*
%{_mandir}/man1/postgres.*
%{_mandir}/man1/postmaster.*
%dir %{_datadir}
%{_datadir}/postgres.bki
%{_datadir}/postgres.description
%{_datadir}/postgres.shdescription
%{_datadir}/system_views.sql
%{_datadir}/*.sample
%{_datadir}/timezone/
%{_datadir}/timezonesets/
%{_datadir}/conversion_create.sql
%{_datadir}/information_schema.sql
%{_datadir}/sql_features.txt
%{_datadir}/sepostgresql.pp
%{_libdir}
%{_libdir}/plpgsql.so
%{_libdir}/libpq.*
%{_libdir}/libpgtypes.*
%{_libdir}/*_and_*.so
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/data
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/backups
/var/lib/sepgsql/.bash_profile

%changelog
* Tue Feb 27 2007  <kaigai@kaigai.gr.jp>
- Initial RPM build
