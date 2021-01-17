%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: clipboard-sync
Summary: Secure clipboard sync across your devices
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: LICENSE
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://github.com/songokas/clipboard-sync

Requires: xcb-util

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/lib/systemd/user/%{name}.service
%{_bindir}/*
