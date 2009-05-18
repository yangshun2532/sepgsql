%define selinux_policy_types targeted mls

Name: mod_selinux
Version: 2.2.%%__mod_selinux_revision__%%
Release: 1%{?dist}
Summary: Apache/SELinux plus modules
Group: System Environment/Daemons
License: ASL 2.0
URL: http://code.google.com/p/sepgsql/
Source0: http://sepgsql.googlecode.com/files/%{name}-%{version}.tgz
Source1: %{name}.conf
Source2: %{name}.map
BuildRequires: httpd-devel >= 2.2.0 libselinux-devel checkpolicy >= 2.0.19 selinux-policy
Requires: kernel >= 2.6.28 httpd >= 2.2.0 libselinux policycoreutils selinux-policy
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
The Apache/SELinux plus is a set of modules to launch web applications
under the restrictive privileges set (mod_selinux.so), to provide advanced
authentication mechanism using SE-PostgreSQL (mod_auth_sepgsql.so), and to
define the set of access control policies (mod_selinux.pp).

%prep
%setup -q

%build
# mod_selinux.so
%{__make} %{?_smp_mflags}

# mod_selinux.pp
for policy in %{selinux_policy_types}
do
    %{__make} NAME=${policy} -f %{?policy_devel_root}%{_datadir}/selinux/devel/Makefile
    mv %{name}.pp %{name}.pp.${policy}
done

%install
rm -rf %{buildroot}
%{__install} -d %{buildroot}%{_libdir}/httpd/modules
%{__install} -d %{buildroot}%{_datadir}/selinux
%{__install} -d %{buildroot}%{_sysconfdir}/httpd/conf.d
%{__install} -d %{buildroot}%{_var}/www

%{__make} install DESTDIR=%{buildroot}

%{__install} -p -m 644 %{SOURCE1}       %{buildroot}%{_sysconfdir}/httpd/conf.d
%{__install} -p -m 644 %{SOURCE2}       %{buildroot}%{_var}/www
for policy in %{selinux_policy_types}
do
    %{__install} -d %{buildroot}%{_datadir}/selinux/${policy}
    %{__install} -p -m 644 %{name}.pp.${policy} \
               %{buildroot}%{_datadir}/selinux/${policy}/%{name}.pp
done

%clean
rm -rf %{buildroot}

%post
/sbin/fixfiles -R %{name} restore || :

for policy in %{selinux_policy_types}
do
    %{_sbindir}/semodule -s ${policy} \
        -i %{_datadir}/selinux/${policy}/%{name}.pp 2>/dev/null || :
done

%postun
# unload policy, if rpm -e
if [ $1 -eq 0 ]; then
    for policy in %{selinux_policy_types}
    do
        %{_sbindir}/semodule -s ${policy} -r %{name} 2>/dev/null || :
    done
fi

%files
%defattr(-,root,root,-)
%doc LICENSE README
%config(noreplace) %{_sysconfdir}/httpd/conf.d/%{name}.conf
%config(noreplace) %{_var}/www/%{name}.map
%{_libdir}/httpd/modules/%{name}.so
%{_datadir}/selinux/*/%{name}.pp

%changelog
* Mon May 18 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1900-1
- rework: add selinux_merge_conf()
- rework: remove mod_authn_sepgsql, instead of documentation
          to use mod_authn_dbd with pgsql driver.

* Fri May 15 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1898-1
- rework: mod_authn_sepgsql cleanups
- update: README updates.

* Wed May 13 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1884-1
- rework: add mod_authn_sepgsql module
- rework: directives were reorganized
- rework: simultaneous usage with keep-alive

* Fri Apr 17 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1817-1
- bugfix: add kernel >= 2.6.28 because of typebounds feature

* Thu Apr 16 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1803-1
- rework: reverted to multi-threading design
- bugfix: security policy didn't allow prosess:{setcurrent}

* Wed Apr 15 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1800-1
- rework: worker was redesigned to use a process, instead of thread,
          on process_connection hook.
- rework: "selinuxAllowCaches" and "selinuxAllowKeepAlive" were added.
- rework: README was revised

* Tue Apr 14 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1795-1
- bugfix: install script didn't work correctly.
- update: add some of inline source comments.
- update: specfile improvement.

* Sun Apr 12 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1792-1
- Initial build
