%define selinux_policy_types targeted mls

Name: mod_selinux
Version: 2.2.%%__mod_selinux_revision__%%
Release: 1%{?dist}
Summary: Apache/SELinux plus (module)
Group: System Environment/Daemons
License: ASL 2.0
URL: http://code.google.com/p/sepgsql/
Source0: %{name}-%{version}.tgz
Source1: %{name}.conf
Source2: %{name}.map
BuildRequires: httpd-devel checkpolicy selinux-policy
Requires: httpd >= 2.2.0 policycoreutils selinux-policy
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
The Apache/SELinux plus (module) enables to launch web
applications under the more restrictive privileges of
SELinux for each requests. It also means we can associate
a concept of web-users and a set of privileges on the
operating system.
Internally, it spawns a one-time thread for each request
at the process_connection hook and assigns an appropriate
privileges at the fixups hook based on http-authentication
or remote addresses. In addition, it always disables
contents caches because it enables users to bypass access
controls.
Please note that it may give us performance impact, but
we don't assume users of the module give the highest
priority to the performance rather than the security.

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
* Tue Apr 14 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1795
- bugfix: install script didn't work correctly.
- update: add some of inline source comments.
- update: specfile improvement.

* Sun Apr 12 2009 KaiGai Kohei <kaigai@ak.jp.nec.com> - 2.2.1792
- Initial build
