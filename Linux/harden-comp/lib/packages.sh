#!/bin/bash

install_package() {
  local package_manager="$1"
  if [[ -z "$package_manager" ]]; then
    print_status message error "No package manager specified"
    return 1
  fi

  local package_name="$2"
  if [[ -z "$package_name" ]]; then
    print_status message error "No package name specified"
    return 1
  fi

  if [[ "$package_manager" == "unsupported" ]]; then
    print_status message error "Unsupported package manager"
    return 1
  fi

  case "$package_manager" in
    apt)
      print_status using_to info install "apt" "$package_name"
      apt install -y "$package_name"
      ;;
    dnf)
      print_status using_to info install "dnf" "$package_name"
      dnf install -y "$package_name"
      ;;
    yum)
      print_status using_to info install "yum" "$package_name"
      yum install -y "$package_name"
      ;;
    zypper)
      print_status using_to info install "zypper" "$package_name"
      zypper install -y "$package_name"
      ;;
    pacman)
      print_status using_to info install "pacman" "$package_name"
      pacman -Syu --noconfirm "$package_name"
      ;;
    *)
      print_status message error "Unsupported package manager"
      return 1
      ;;
  esac
}

remove_package() {
  local package_manager="$1"
  if [[ -z "$package_manager" ]]; then
    print_status message error "No package manager specified"
    return 1
  fi

  local package_name="$2"
  if [[ -z "$package_name" ]]; then
    print_status message error "No package name specified"
    return 1
  fi

  if [[ "$package_manager" == "unsupported" ]]; then
    print_status message error "Unsupported package manager"
    return 1
  fi

  case "$package_manager" in
    apt)
      print_status using_to info remove "apt" "$package_name"
      apt remove "$package_name"
      ;;
    dnf)
      print_status using_to info remove "dnf" "$package_name"
      dnf remove "$package_name"
      ;;
    yum)
      print_status using_to info remove "yum" "$package_name"
      yum remove "$package_name"
      ;;
    zypper)
      print_status using_to info remove "zypper" "$package_name"
      zypper remove "$package_name"
      ;;
    pacman)
      print_status using_to info remove "pacman" "$package_name"
      pacman -R "$package_name"
      ;;
    *)
      print_status message error "Unsupported package manager"
      return 1
      ;;
  esac
}

upgrade_system() {
  local package_manager="$1"
  if [[ -z "$package_manager" ]]; then
    echo "Error: No package manager provided to upgrade_system."
    return 1
  fi

  if [[ "$package_manager" == "unsupported" ]]; then
    echo "Error: Unsupported operating system."
    return 1
  fi

  case "$package_manager" in
    apt)
      echo "Using apt to upgrade system..."
      apt update && apt upgrade -y
      ;;
    dnf)
      echo "Using dnf to upgrade system..."
      dnf upgrade -y
      ;;
    yum)
      echo "Using yum to upgrade system..."
      yum upgrade -y
      ;;
    zypper)
      echo "Using zypper to upgrade system..."
      zypper up
      ;;
    pacman)
      echo "Using pacman to upgrade system..."
      pacman -Syu --noconfirm
      ;;
    *)
      echo "Error: Unsupported package manager."
      return 1
      ;;
  esac
}

# CIS Debian 2.1 & 2.2
check_installed_packages() {
  PACKAGES=()
  local pkg=""
  case $DISTRO in
    ubuntu | debian)
      local -ar candidate_pkgs=(
        autofs avahi-daemon isc-dhcp-server bind9 dnsmasq vsftpd slapd
        dovecot-imapd nfs-kernel-server ypserv cups rpcbind rsync samba
        snmpd tftpd-hpa squid apache2 nginx xinetd xserver-common nis
        rsh-client talk telnet inetutils-telnet ldap-utils ftp tnftp
        prelink apport gnome gdm3 bluez netcat-openbsd netcat-traditional
        ncat wireshark tshark tcpdump gcc make rsh-server telnetd nmap
        proftpd pure-ftpd inetutils-inetd openbsd-inetd rinetd rlinetd
        unbound lighttpd vnc-server tightvncserver
        tigervnc-standalone-server linuxvnc x11vnc cockpit
      )
      for pkg in "${candidate_pkgs[@]}"; do
        { dpkg-query -s "$pkg" &> /dev/null && PACKAGES+=("$pkg"); } \
          || :
      done
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      local -ar candidate_pkgs=(
        mcstrans setroubleshoot autofs avahi dhcp-server bind dnsmasq
        samba vsftpd dovecot cyrus-imapd nfs-utils ypserv cups
        rpcbind rsync-daemon net-snmp telnet-server tftp-server squid
        httpd nginx xinetd xorg-x11-server-common ftp openldap-clients
        ypbind telnet tftp @graphical-server-environment
        @workstation-product-environment gdm bluez netcat nmap-ncat wireshark
        wireshark-cli tcpdump gcc make rsh rsh-server nmap proftpd
        pure-ftpd unbound lighttpd tigervnc-server
        tigervnc-server-minimal cockpit
      )
      for pkg in "${candidate_pkgs[@]}"; do
        { rpm -q "$pkg" &> /dev/null && PACKAGES+=("$pkg"); } || :
      done
      ;;
    opensuse*)
      local -ar candidate_pkgs=(
        autofs avahi dhcp-server bind dnsmasq samba openldap2 vsftpd dovecot
        cyrus-imapd nfs-kernel-server ypserv cups rpcbind rsync net-snmp
        telnet-server tftp-server squid apache2 nginx xinetd xorg-x11-server
        xorg-x11-server* ftp openldap2-client openldap2_5 ypbind telnet tftp
        gnome gnome_x11 gdm bluez netcat-openbsd busybox-netcat wireshark
        tcpdump gcc make mrsh mrsh-server nmap proftpd pure-ftpd rinetd xinetd
        unbound lighttpd tigervnc x11vnc xorg-x11-Xvnc wayvnc cockpit
      )
      for pkg in "${candidate_pkgs[@]}"; do
        { rpm -q "$pkg" &> /dev/null && PACKAGES+=("$pkg"); } || :
      done
      ;;
    *)
      print_status message error "Unsupported package manager"
      return 1
      ;;
  esac
}

# CIS Ubuntu 2.1 & 2.2
# Requires user interaction
ask_to_remove_packages() {
  if [ ${#PACKAGES[@]} -eq 0 ]; then
    print_status message warn \
      "There are no packages to remove (Did you use -P by accident?)"
    return 0
  fi
  echo -e "${BLUE}You will be asked if you want to remove each package${NC}"
  echo -e "${BLUE}look carefully at each, and determine if they are necessary or not.${NC}"
  local pkg
  for pkg in "${PACKAGES[@]}"; do
    remove_package "$PKG_MANAGER" "$pkg" || true
  done
  return 0
}

install_recommended_packages() {
  local journal_remote="false"
  local rsyslog="false"
  local extra_security="false"
  local arg=""

  for arg in "$@"; do
    case "$arg" in
      journal_remote=true) 
        journal_remote="true"
        ;;
      journal_remote=false)
        journal_remote="false"
        ;;
      rsyslog=true)
        rsyslog="true"
        ;;
      rsyslog=false)
        rsyslog="false"
        ;;
      extra_security=true)
        extra_security="true"
        ;;
      extra_security=false)
        extra_security="false"
        ;;
      *)
        print_status message_object error option "Unrecognized option:" "$arg"
        return 1
        ;;
    esac
  done

  case "$DISTRO" in
    ubuntu | debian)
      local -a packages=(
        "sudo" "apparmor" "apparmor-utils" "auditd" "audispd-plugins" "aide"
        "apparmor-profiles" "apparmor-profiles-extra"
      )
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      local -a packages=(
        "sudo" "libselinux" "audit" "aide" "selinux-policy"
        "selinux-policy-targeted"
      )
      ;;
    opensuse*)
      local -a packages=(
        "sudo" "apparmor-parser" "apparmor-profiles" "apparmor-utils"
        "libapparmor1" "audit" "aide"
      )
      ;;
    *)
      print_status message error "Unrecognized package manager"
      return 1
      ;;
  esac

  local pkg
  if [ "$journal_remote" = "true" ]; then
    packages+=("systemd-journal-remote")
  elif [ "$rsyslog" = "true" ]; then
    packages+=("rsyslog")
  fi
  if [ "$extra_security" = "true" ]; then
    packages+=("lynis" "clamav" "chkrootkit" "fail2ban")
  fi

  for pkg in "${packages[@]}"; do
    install_package "$PKG_MANAGER" "$pkg"
  done
}

download_software() {
  if command -v wget &> /dev/null; then
    wget -qO ./tools/linpeas.sh \
      "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
    wget -qO ./tools/maldetect-current.tar.gz \
      "https://www.rfxn.com/downloads/maldetect-current.tar.gz"
    print_status message_object success command "Downloaded files with" "wget"
  elif command -v curl &> /dev/null; then
    curl -sOJ \
      https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
      --output-dir ./tools
    curl -sOJ \
      https://www.rfxn.com/downloads/maldetect-current.tar.gz \
      --output-dir ./tools
    print_status message_object success command "Downloaded files with" "curl"
  else
    print_status message error "Ensure you have wget or curl installed"
  fi
}
