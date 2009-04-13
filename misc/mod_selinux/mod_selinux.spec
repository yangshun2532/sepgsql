%define selinux_policy_types targeted mls

Name: mod_selinux
Version: 2.2.%%__mod_selinux_revision__%%
Release: 1%{?dist}
Summary: Apache/SELinux plus module
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
Apache/SELinux plus module. 

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
    %{_sbindir}/semodule -s ${policy} -r %{name} >& /dev/null || :
    %{_sbindir}/semodule -s ${policy} \
            -i %{_datadir}/selinux/${policy}/%{name}.pp >& /dev/null || :
done

%postun
if [ $1 -eq 0 ]; then
    for policy in %{selinux_policy_types}
    do
        %{_sbindir}/semodule -s ${policy} -r %{name} >& /dev/null || :
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
* Sun Apr 12 2009 KaiGai Kohei <kaigai@kaigai.gr.jp> 2.2.1792
- Initial build
