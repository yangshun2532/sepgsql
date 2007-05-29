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
Version: 8.2.4
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
Requires: policycoreutils >= 1.33.12-1 selinux-policy >= 2.4.6-40

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
make -f /usr/share/selinux/devel/Makefile NAME=targeted
mv sepostgresql.pp sepostgresql-targeted.pp
make -f /usr/share/selinux/devel/Makefile NAME=strict
mv sepostgresql.pp sepostgresql-strict.pp
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
	${ALTROOT}%{_bindir}/pg_dump			\
	${ALTROOT}%{_bindir}/pg_dumpall			\
	${ALTROOT}%{_bindir}/pg_restore			\
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

install -d $RPM_BUILD_ROOT%{_prefix}/policy
install -m 644 policy/sepostgresql*.pp	$RPM_BUILD_ROOT%{_prefix}/policy

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
if [ $1 -eq 1 ]; then		# rpm -i cases
	groupadd -r sepgsql >& /dev/null || :
	useradd -g sepgsql -d /var/lib/sepgsql -s /bin/bash \
		-r -c "SE-PostgreSQL server" sepgsql >& /dev/null || :
fi

%post
chkconfig --add sepostgresql
/sbin/ldconfig

SELINUXTYPE=`grep ^SELINUXTYPE /etc/selinux/config | sed 's/^.*=//g'`
SEPGSQL_POLICY="%{_prefix}/policy/sepostgresql-${SELINUXTYPE}.pp"
if [ -e ${SEPGSQL_POLICY} ]; then
	SEPGSQL_PREV=`semodule -l | grep -c ^sepostgresql`
	test ${SEPGSQL_PREV} -gt 0 && semodule -n -r sepostgresql || :
	semodule -i ${SEPGSQL_POLICY} || :

	/sbin/restorecon -R -v %{_prefix}
	/sbin/restorecon -R -v /var/lib/sepgsql
	/sbin/restorecon    -v /etc/rc.d/init.d/sepostgresql
fi

%postun
/sbin/ldconfig
if [ $1 -eq 0 ]; then		# rpm -e cases
	userdel  sepgsql >& /dev/null || :
	groupdel sepgsql >& /dev/null || :
	SEPGSQL_PREV=`semodule -l | grep -c ^sepostgresql`
	test ${SEPGSQL_PREV} -gt 0 && semodule -r sepostgresql || :
elif [ $1 -eq 1 ]; then		# rpm -Uvh cases
	/sbin/service sepostgresql condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
/etc/rc.d/init.d/sepostgresql
%dir %{_prefix}
%dir %{_bindir}
%{_bindir}/initdb
%{_bindir}/ipcclean
%{_bindir}/pg_controldata
%{_bindir}/pg_ctl
%{_bindir}/pg_resetxlog
%{_bindir}/postgres
%{_bindir}/postmaster
%{_bindir}/pg_dump
%{_bindir}/pg_dumpall
%{_bindir}/pg_restore
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
%dir %{_libdir}
%{_libdir}/plpgsql.so
%{_libdir}/libpq.*
%{_libdir}/libpgtypes.*
%{_libdir}/*_and_*.so
%dir %{_prefix}/policy
%{_prefix}/policy/sepostgresql*.pp
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/data
%attr(700,sepgsql,sepgsql) %dir /var/lib/sepgsql/backups
/var/lib/sepgsql/.bash_profile

%changelog
* Tue May 29 2007 <kaigai@kaigai.gr.jp>
- BUGFIX: RangeTblEntry->requiredPerms are polluted.

* Sun May 27 2007 <kaigai@kaigai.gr.jp>
- add support for dynamic object class/access vector mapping
- BUGFIX: Lack of implicit labeling on COPY FROM statement for system catalogs
- BUGFIX: Incorrect security context handling for inherited tables

* Fri May 25 2007 <kaigai@kaigai.gr.jp>
- add pg_dump/pg_dumpall/pg_restore with --enable-security option
- add support on OUTER JOIN by rewriting query.
- add security_context support on COPY TO/FROM statement
- add unlabeled security context support (enable to obtain /selinux/initial_contexts/*)
- BUGFIX: lack of checks on JOIN ON condition
- BUGFIX: pseudo relation object (sequence, toast, ...) are not handled as database obj.
- BUGFIX: lack of tuple:insert checks at COPY FROM statement
- BUGFIX: server crash when CREATE TABLE command with newly defined CONTEXT = '...'.

* Wed May 16 2007 <kaigai@kaigai.gr.jp>
- BUGFIX: incorrect security context of newly generated system object.
- BUGFIX: missing error text when audit log is disabled.
- BUGFIX: incorrect Oid of newly generated tuples within pg_security.
- BUGFIX: sepgsql_enable_audittuple is misconditioned.
- add checks for T_RowExpr/T_RowCompareExpr/T_BooleanTest
                 T_DistinctExpr/T_ConvertRowtypeExpr
- add support CONTEXT = 'xxx' for CREATE TABLE/FUNCTION/DATABASE statement

* Sun Apr 30 2007 <kaigai@kaigai.gr.jp>
- update base version 8.2.3 -> 8.2.4
- BUGFIX: unexpected expose in OUTER JOIN statement.
          add rewrite OUTER JOIN into SUBQUERY to ensure filtering violated tuples.
- BUGFIX: strange operation in text_to_security_label()
- BUGFIX: infinite recursive call on security label -> oid mapping
- BUGFIX: sepgsql_avc_init() is called in policy state monitoring process
          to avoid nonsense initialization of avc_shmem.

* Fri Apr 27 2007 <kaigai@kaigai.gr.jp>
- object class numbers were redefined. (SECCLASS_DATABASE got into 61)
- is_selinux_enabled() was cached on the shared memory segment.
- BUGFIX: server went into infinit loop on foreign key constraint.

* Mon Apr 16 2007 <kaigai@kaigai.gr.jp>
- BUGFIX: cases when several variables with same type in a single table

* Sat Apr 07 2007 <kaigai@kaigai.gr.jp>
- add the first implementation of SE-PostgreSQL on PGACE framework

* Wed Mar 21 2007 <kaigai@kaigai.gr.jp>
- BUGFIX: SetOperation didn't handle its subquery correctly.
  So, it caused server crash.

* Wed Mar 07 2007 <kaigai@kaigai.gr.jp>
- BUGFIX: var->varlevelsup was ignored, so outer references
  from subqueries cause a fault.

* Tue Feb 27 2007  <kaigai@kaigai.gr.jp>
- Initial RPM build
