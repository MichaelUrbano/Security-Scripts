#!/bin/bash

# CIS 6.2.3 (Ubuntu), 6.3.3 (RHEL)
configure_auditd() {
  if ! command -v auditctl &> /dev/null; then
    print_status message error "Please ensure auditd is installed"
    return 1
  fi
  if [[ ! -f /etc/audit/auditd.conf ]]; then
    print_status not_found error file "/etc/audit/auditd.conf"
    return 1
  fi
  if [[ ! -d /etc/audit/rules.d ]]; then
    print_status not_found error directory "/etc/audit/rules.d"
    return 1
  fi
  if [[ -f /etc/audit/rules.d/99-hardening.rules ]]; then
    print_status already_exists error file "99-hardening.rules" rude
    return 1
  fi

  # 6.2.2 (Ubuntu), 6.3.2 (RHEL)
  print_status message_object info file "Configuring" "/etc/audit/auditd.conf"
  if grep -qE \
    "^[[:blank:]]*max_log_file[[:blank:]]+=[[:blank:]]+[0-9]+$" \
    /etc/audit/auditd.conf; then
    if ! grep -qE \
      "^[[:blank:]]*max_log_file[[:blank:]]+=[[:blank:]]+([8-9]|[1-9][0-9]{1,2}|1000)$" \
      /etc/audit/auditd.conf; then
      sed -iE \
        's/^[[:blank:]]*max_log_file[[:blank:]]+=[[:blank:]]+[0-9]+$/max_log_file = 8/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "max_log_file = 8" >> /etc/audit/auditd.conf
  fi
  if grep -qiE \
    "^[[:blank:]]*max_log_file_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$" \
    /etc/audit/auditd.conf; then
    if ! grep -qiE \
      "^[[:blank:]]*max_log_file_action[[:blank:]]+=[[:blank:]]+keep_logs$" \
      /etc/audit/auditd.conf; then
      sed -iE \
        's/^[[:blank:]]*max_log_file_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/max_log_file_action = keep_logs/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
  fi
  # We explicitly do not follow the CIS Security Benchmark recommendations here,
  # disk_full_action = halt|single results in a loss of availability
  if grep -qiE \
    "^[[:blank:]]*disk_full_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*disk_full_action[[:blank:]]+=[[:blank:]]+(syslog|rotate)$"; then
      sed -iE \
        's/^[[:blank:]]*disk_full_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/disk_full_action = rotate/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "disk_full_action = rotate" >> /etc/audit/auditd.conf
  fi
  if grep -qiE \
    "^[[:blank:]]*disk_error_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*disk_error_action[[:blank:]]+=[[:blank:]]+syslog$"; then
      sed -iE \
        's/^[[:blank:]]*disk_error_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/disk_error_action = syslog/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "disk_error_action = syslog" >> /etc/audit/auditd.conf
  fi
  # Once again explicitly not following CIS Security Benchmarks
  # space_left_action|admin_space_left_action = halt|single
  # Either values result in a loss of availability.
  if grep -qiE \
    "^[[:blank:]]*space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*space_left_action[[:blank:]]+=[[:blank:]]+(email|rotate)$"; then
      sed -iE \
        's/^[[:blank:]]*space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/space_left_action = email/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "space_left_action = email" >> /etc/audit/auditd.conf
  fi
  if grep -qiE \
    "^[[:blank:]]*admin_space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*admin_space_left_action[[:blank:]]+=[[:blank:]]+(email|rotate)$"; then
      sed -iE \
        's/^[[:blank:]]*admin_space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/admin_space_left_action = email/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "admin_space_left_action = email" >> /etc/audit/auditd.conf
  fi
  print_status message_object success file \
    "Finished configuring" "/etc/audit/auditd.conf"

  print_status message_object info file \
    "Adding rules to" "/etc/audit/rules.d/99-hardening.rules"
  cat << 'EOF' > /etc/audit/rules.d/99-hardening.rules
# These rules were added by harden-comp.sh

# 6.2.3.1/6.3.3.1
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# 6.2.3.2/6.3.3.2
-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation
-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation

# 6.2.3.3/6.3.3.3
-w /var/log/sudo.log -p wa -k sudo_log_file

# 6.2.3.4/6.3.3.4
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change

# 6.2.3.5/6.3.3.5 (partial)
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale

# 6.2.3.6/6.3.3.6
# Not yet implemented

# 6.2.3.7/6.3.3.7
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

# 6.2.3.8/6.3.3.8
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity

# 6.2.3.9/6.3.3.9
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

# 6.2.3.10/6.3.3.10
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

# 6.2.3.11/6.3.3.11
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# 6.2.3.12/6.3.3.12
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# 6.2.3.13/6.3.3.13
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

# 6.2.3.15/6.3.3.15
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.2.3.16/6.3.3.16
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.2.3.17/6.3.3.17
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.2.3.18/6.3.3.18
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod

# 6.2.3.19/6.3.3.19
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules

EOF
  case "$DISTRO" in
    ubuntu | debian)
      cat << 'EOF' >> /etc/audit/rules.d/99-hardening.rules
# 6.2.3.5 (Ubuntu)
-w /etc/networks -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale

# 6.2.3.14 (Ubuntu)
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# 6.2.3.20
-e 2
EOF
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      cat << 'EOF' >> /etc/audit/rules.d/99-hardening.rules
# 6.3.3.5 (RHEL)
-w /etc/hostname -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/NetworkManager -p wa -k system-locale

# 6.3.3.14 (RHEL)
-w /etc/selinux -p wa -k MAC-policy
-w /usr/share/selinux -p wa -k MAC-policy

# 6.3.3.20
-e 2
EOF
      ;;
    opensuse*)
      cat << 'EOF' >> /etc/audit/rules.d/99-hardening.rules
# 6.3.3.5 (SUSE)
-w /etc/hostname -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/NetworkManager -p wa -k system-locale

# 6.3.3.14 (SUSE)
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# 6.3.3.20
-e 2
EOF
      ;;
    *)
      cat << 'EOF' >> /etc/audit/rules.d/99-hardening.rules
# 6.2.3.20/6.3.3.20
-e 2
EOF
      ;;
  esac
  augenrules --load
  augenrules --check
  systemctl enable --now auditd
  print_status message success "Configured auditd"
}

# CIS Ubuntu 6.1.1-2, RHEL 6.2.1-2
configure_logging() {
  if ! command -v journalctl &> /dev/null; then
    print_status message error "Please ensure systemd-journald is installed"
    return 1
  fi
  if [[ ! -d /etc/systemd/journald.conf.d ]]; then
    mkdir -p /etc/systemd/journald.conf.d
  fi

  local journal_remote_installed="false"
  local rsyslog_installed="false"
  local journal_remote="false"
  local rsyslog="false"
  local arg=""

  for arg in "$@"; do
    case "$arg" in
      journal_remote=true) journal_remote="true" ;;
      journal_remote=false) journal_remote="false" ;;
      rsyslog=true) rsyslog="true" ;;
      rsyslog=false) rsyslog="false" ;;
      *)
        print_status message_object error option "Unrecognized option:" "$arg"
        return 1
        ;;
    esac
  done

  if [[ "$DISTRO" =~ ^(debian|ubuntu)$ ]]; then {
    dpkg-query -s systemd-journal-remote &> /dev/null \
    && journal_remote_installed="true";
    } || :
    {
    dpkg-query -s rsyslog &> /dev/null \
    && rsyslog_installed="true";
  } || :
  elif [[ "$DISTRO" =~ ^(centos|rocky|almalinux|fedora|rhel|ol|opensuse.*)$ ]]; then {
    rpm -q systemd-journal-remote &> /dev/null \
    && journal_remote_installed="true"
    } || :
    {
    rpm -q rsyslog &> /dev/null \
    && rsyslog_installed="true"
  } || :
  fi

  # Configure journald
  if [[ -f /etc/systemd/journald.conf.d/99-hardening.conf ]]; then
    print_status message warn already_exists file \
      "/etc/systemd/journald.conf.d/99-hardening" rude
  else
    cat << 'EOF' > /etc/systemd/journald.conf.d/99-hardening.conf
# Generated by harden-comp.sh
[Journal]
Compress=yes
Storage=persistent
SystemMaxUse=1G
SystemKeepFree=500M
RuntimeMaxUse=200M
RuntimeKeepFree=50M
MaxFileSec=1month
ForwardToSyslog=no
EOF
    if [[ "$rsyslog" == "true" ]]; then
      sed -i 's/ForwardToSyslog=no/ForwardToSyslog=yes/' /etc/systemd/journald.conf.d/99-hardening.conf
    fi
  fi
  systemctl enable --now systemd-journald
  print_status message success "Configured journald"

  # Configurations for systemd-journal-remote or rsyslog are done here 
  if [[ "$journal_remote_installed" == "true" && "$journal_remote" == "true" ]]; then
    if [[ ! -d /etc/systemd/journal-upload.conf.d ]]; then
      mkdir -p /etc/systemd/journal-upload.conf.d
    fi
    if [[ -f /etc/systemd/journal-upload.conf.d/99-hardening.conf ]]; then
      print_status already_exists error file \
        "/etc/systemd/journal-upload.conf.d/99-hardening.conf"
      return 0
    fi
    cat << 'EOF' > /etc/systemd/journal-upload.conf.d/99-hardening.conf
# Generated by harden-comp.sh
# This is simply a template, which should be modified as necessary
[Upload]
#URL=<replace_with_ip_or_url>
ServerKeyFile=/etc/ssl/private/journal-upload.pem
ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
TrustedCertificateFile=/etc/ssl/ca/trusted.pem
EOF
    print_status message_object info directory \
      "Template systemd-journal-upload configuration file created at" \
      "/etc/systemd/journal-upload.conf.d/99-hardening.conf"
    systemctl enable --now systemd-journal-upload
    systemctl mask --now systemd-journal-remote.service || :
    systemctl mask --now systemd-journal-remote.socket || :
    print_status message success "Configured systemd-journal-remote"
  elif [[ "$rsyslog_installed" == "true" && "$rsyslog" == "true" ]]; then
    if [[ ! -d /etc/rsyslog.d ]]; then
      mkdir -p /etc/rsyslog.d
    fi
    if [[ -f /etc/rsyslog.d/99-hardening.conf ]]; then
      print_status already_exists error file \
        "/etc/rsyslog.d/99-hardening.conf"
      return 0
    fi
    cat << 'EOF' > /etc/rsyslog.d/99-hardening.conf
# Generated by harden-comp.sh
# This is simply a template, which should be modified as necessary
$FileCreateMode 0640
#*.* action(type="omfwd" target="<replace_with_ip_or_url>" port="514" protocol="tcp")
# Please review /etc/logrotate.d/rsyslog
# Ensure that this server is not configured to receive logs
EOF
    systemctl enable --now rsyslog
  elif [[ "$journal_remote_installed" == "false" && "$journal_remote" == "true" ]]; then
    print_status not_installed error "systemd-journal-remote"
  elif [[ "$rsyslog_installed" == "false" && "$rsyslog" == "true" ]]; then
    print_status not_installed error "rsyslog"
  fi
}

configure_aide() {
  command -v aide &>/dev/null || {
    print_status message error "Please ensure AIDE is installed."
    return 1
  }
  case "$DISTRO" in
    ubuntu | debian)
      aideinit
      mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      aide --init
      mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
      ;;
    opensuse*)
      aide -i
      /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      ;;
    *)
      print_status message error \
        "Unsupported distribution, cannot configure"
      return 1
      ;;
  esac
  systemctl enable --now dailyaidecheck.timer
  print_status message success "AIDE configured"
}
