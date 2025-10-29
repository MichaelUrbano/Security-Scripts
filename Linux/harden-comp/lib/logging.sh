# CIS 6.2.3 (Ubuntu), 6.3.3 (RHEL)
configure_auditd() {
  if ! command -v auditctl; then
    print_status message error "Please ensure auditd is installed"
    return 1
  fi
  if [[ ! -f /etc/audit/auditd.conf ]]; then
    print_status not_found error file "/etc/audit/auditd.conf"
    return 1
  fi
  if [[ ! -d /etc/audit/rules.d || -f /etc/audit/rules.d/99-hardening.rules ]]; then
    print_status not_found error directory "/etc/audit/rules.d"
    return 1
  fi
  if [[ -f /etc/audit/rules.d/99-hardening.rules ]]; then
    print_status already_exists error file "99-hardening.rules"
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
  cat <<'EOF' | tee /etc/audit/rules.d/99-hardening.rules
# These rules were added by Michael's Linux Hardening Script

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
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
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
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
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
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
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
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
# 6.2.3.20/6.3.3.20
-e 2
EOF
      ;;
  esac
  augenrules --load
  augenrules --check
  systemctl enable --now auditd
}

configure_logging() {
  return 0
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
    *)
      print_status message error \
        "Unsupported distribution, cannot configure"
      return 1
      ;;
  esac
  systemctl enable --now dailyaidecheck.timer
}