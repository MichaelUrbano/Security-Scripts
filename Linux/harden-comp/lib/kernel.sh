# CIS Ubuntu 12: 1.1.1.1-5,8-9, 3.2
# 1.1.1.10 to be added
# Will disable unnecessary kernel modules
disable_kernel_modules() {
  local -a modules=(
    "cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage"
    "dccp" "tipc" "rds" "sctp"
  )
#  local -a extra_modules=(
#    "afs" "ceph" "cifs" "exfat" "ext" "fat" "fscache" "fuse" "gfs2"
#    "nfs_common" "nfsd" "smbfs_common"
#  )
  if "$DISTRO" != "ubuntu" && ! command -v snap; then
    modules+=("squashfs")
  fi
  local hardening_blacklist="/etc/modprobe.d/hardening-blacklist.conf"
  touch "$hardening_blacklist"
  local mod
  # Check for duplicates entries, then add an entry if it doesn't exist.
  for mod in "${modules[@]}"; do
    if ! grep -qE "^install[[:blank:]]+${mod}[[:blank:]]+" "$hardening_blacklist"; then
      echo "install $mod /bin/false" >>"$hardening_blacklist"
    fi
  done
}

# Configure sysctl parameters to harden the system
# CIS Ubuntu 12: 3.1.1
configure_sysctl() {
  local disable_ipv6="false"
  local sysctl_file="/etc/sysctl.d/99-hardening.conf"
  local limits_file="/etc/security/limits.d/99-hardening.conf"

  local arg=""
  for arg in "$@"; do
    case "$arg" in
      disable_ipv6=true) disable_ipv6="true" ;;
      disable_ipv6=false) disable_ipv6="false" ;;
      *)
        echo "Unrecognized argument: $arg" >&2
        return 1
        ;;
    esac
  done

  declare -A settings=(
    ["kernel.randomize_va_space"]="2"
    ["kernel.yama.ptrace_scope"]="2"
    ["fs.suid_dumpable"]="0"
    ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.conf.all.rp_filter"]="2"
    ["net.ipv4.conf.default.rp_filter"]="2"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.conf.default.log_martians"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
  )

  if [ $disable_ipv6 = "true" ]; then
    settings["net.ipv6.conf.all.disable_ipv6"]="0"
  fi

  if [ ! -d "/etc/sysctl.d" ]; then
    print_status not_found error directory "/etc/sysctl.d"
    return 1
  fi
  if [ -f "$sysctl_file" ]; then
    print_status already_exists error file "$sysctl_file" kind
    return 1
  fi

  # This simply iterates through each element and appends it to the file,
  # Additionally it sets it up via sysctl.
  local value
  for key in "${!settings[@]}"; do
    value="${settings[$key]}"
    echo "${key} = ${value}" >>"$sysctl_file"
    sysctl -w "${key}=${value}" &>/dev/null
  done

  if [ ! -d "/etc/security/limits.d" ]; then
    print_status not_found error directory "/etc/security/limits.d"
    return 1
  fi
  if [ -f "$limits_file" ]; then
    print_status already_exists error file "$sysctl_file" kind
    return 1
  fi
  # Disable core dumps
  echo "* hard core 0" > "$limits_file"
}

# Will change boot parameters and ensure MAC is enforced
configure_grub() {
  if command -v grubby; then
    grubby --update-kernel ALL --remove-args "selinux=0 enforcing=0"
    grubby --update-kernel="$(grubby --default-kernel)" \
      --args="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"
    print_status message success "Reconfigured GRUB successfully"
    return 0
  fi

  if [[ ! -f /etc/default/grub ]]; then
    print_status not_found error file "/etc/default/grub"
    return 1
  fi

  if grep -qE '^[[:blank:]]*GRUB_CMDLINE_LINUX="[[:blank:]]*"$' /etc/default/grub; then
    sed -i -E \
      's/^[[:blank:]]*GRUB_CMDLINE_LINUX="[[:blank:]]*"$/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"/' \
      /etc/default/grub
  elif grep -qE '^[[:blank:]]*GRUB_CMDLINE_LINUX=".*"$' /etc/default/grub; then
    sed -i -E \
      's/^[[:blank:]]*(GRUB_CMDLINE_LINUX=".*)"/\1 apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"/' \
      /etc/default/grub
  elif ! grep -qE '^[[:blank:]]*GRUB_CMDLINE_LINUX=".*"$' /etc/default/grub; then
    echo GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192" >>/etc/default/grub
  else
    print_status message_alt error \
      "Failed to append to " "/etc/default/grub"
    printf "%b%s%b" "$YELLOW" "/etc/default/grub" "$NC"
    return 1
  fi

  if grep -qE 'selinux=0|enforcing=0' /etc/default/grub; then
    sed -i 's/\bselinux=0\b//g; s/\benforcing=0\b//g' /etc/default/grub
  fi

  if command -v update-grub; then
    update-grub
  elif command -v grub2-mkconfig && [[ -f /boot/grub2/grub.cfg ]]; then
    grub2-mkconfig -o /boot/grub2/grub.cfg
  else
    print_status message error "Please manually run update-grub"
    return 1
  fi

  print_status message success "Reconfigured GRUB successfully"
}

configure_mac() {
  case "$DISTRO" in
    ubuntu | debian | opensuse*)
      if ! command -v aa-enforce; then
        print_status message_object error command \
          "Could not run" "aa-enforce"
        return 1
      fi
      aa-enforce /etc/apparmor.d/* &>/dev/null || true
      aa-complain /usr/share/apparmor/extra-profiles/* || true
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      if ! grep -qE '^[[:blank:]]*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config; then
        sed -iE 's/^[[:blank:]]*SELINUXTYPE=.*\b/SELINUXTYPE=targeted/'
      fi
      if ! grep -qEi '^[[:blank:]]*SELINUX=(enforcing|permissive)' /etc/selinux/config; then
        sed -iE 's/^[[:blank:]]*SELINUX=.*\b/SELINUX=enforcing/'
        setenforce 1
      fi
      if ps -eZ | grep unconfined_service_t; then
        print_status message warn \
          "Please be aware there are unconfined processes on the system"
        ps -eZ | grep unconfined_service_t
      fi
      ;;

  esac
  return 1
}