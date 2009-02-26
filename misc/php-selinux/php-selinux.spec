Summary: SELinux binding for PHP scripting language
Name: php-selinux
Version: %%__version__%%
Release: %%__release__%%%{?dist}
License: PHP
Group: Development/Languages
URL: http://code.google.com/p/sepgsql/
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Source0: %{name}-%{version}.tar.bz2
BuildRequires: php-devel libselinux-devel >= 2.0.43
Requires: php libselinux >= 2.0.43

%description
The php-selinux package is an extension to the PHP Hypertext Preprocessor.
It wraps the libselinux library and provides a set of interfaces to the
PHP runtime engine.
The libselinux is a set of application program interfaces towards in-kernel
SELinux, contains get/set security context, communicate security server,
translate between raw and readable format and so on.

%prep
%setup -q

%build
%{_bindir}/phpize --clean
%{_bindir}/phpize
%configure  --enable-selinux
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
install -D -p -m 0755 modules/selinux.so %{buildroot}%{php_extdir}/selinux.so
install -D -p -m 0644 selinux.ini %{buildroot}%{_sysconfdir}/php.d/selinux.ini

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE README
%config(noreplace) %{_sysconfdir}/php.d/selinux.ini
%{php_extdir}/selinux.so

%changelog
* Tue Feb 24 2009  <kaigai@kaigai.gr.jp> - 0.1616-beta
- Initial package
