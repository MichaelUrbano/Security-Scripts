#!/usr/bin/env bash

# just clear
jclr() {
  if [[ "$ARG_CLEAR" == "disabled" ]]; then
    return 0
  fi
  [ -t 1 ] && clear;
}

# prompt clear
pclr() {
  if [[ "$ARG_CLEAR" == "disabled" ]]; then
    return 0
  fi
  local no_reply
  read -rp "Press enter to continue: " no_reply
  echo "$no_reply" &> /dev/null
  [ -t 1 ] && clear;
}

check_distro() {
  if [[ -f /etc/os-release ]]; then
    # freedesktop.org
    # shellcheck disable=SC1091
    . /etc/os-release
    local distro="unknown", is_supported="false"
    for distro in "${SUPPORTED_DISTROS[@]}"; do
      if [[ "$ID" =~ $distro ]]; then
        is_supported="true"
        break
      fi
    done
    if [[ "$is_supported" != "true" && "$ID_LIKE" != "" ]]; then
      DISTRO=${ID_LIKE%% *}
      VER="?"
    else
      DISTRO=$ID
      VER=$VERSION_ID
    fi

  elif type lsb_release &>/dev/null; then
    # linuxbase.org
    DISTRO=$(lsb_release -si)
    VER=$(lsb_release -sr)
  elif [[ -f /etc/lsb-release ]]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    # shellcheck disable=SC1091
    . /etc/lsb-release
    DISTRO=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
  elif [[ -f /etc/debian_version ]]; then
    # Older Debian/Ubuntu/etc.
    DISTRO=Debian
    VER=$(cat /etc/debian_version)
  elif command -v uname &>/dev/null; then
    # Fall back to uname
    DISTRO=$(uname -s)
    VER=$(uname -r)
  else
    DISTRO="unknown"
    VER="?"
  fi
}

check_package_manager() {
  return 1
}

check_firewall() {
  return 1
}

check_cron() {
  return 1
}

check_ntp() {
  return 1
}

check_mac() {
  return 1
}

check_logging() {
  return 1
}

check_users_and_groups() {
  return 1
}

# Checks system information and sets up global variables needed for functions
init() {
  print_status message info "Checking system information..."
  check_distro
  DISTRO=$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')
  if [[ "$DISTRO" =~ $REGEX_ALL_DISTROS ]]; then
    printf "%bDistribution ID:%b %s %s\n" "${GREEN}" "${NC}" "$DISTRO" "$VER"
  else
    print_status message warn "You are running on an unsupported distribution. Are you testing?"
    printf "%bDistribution ID:%b %b%b%s %s%b\n" "${GREEN}" "${NC}" "${CYAN}" "${BOLD}" "$DISTRO" "$VER" "${NC}"
  fi 

  # Choose correct package manager for distro
  case "$DISTRO" in
    ubuntu | debian)
      if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
      else
        print_status message alert "Using dpkg instead of apt"
        PKG_MANAGER="dpkg"
      fi
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      if command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
      elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
      else
        print_status message alert "Using rpm instead of dnf or yum"
        PKG_MANAGER="rpm"
      fi
      ;;
    sles | opensuse* | suse)
      PKG_MANAGER="zypper"
      ;;
    arch)
      PKG_MANAGER="pacman"
      ;;
    *)
      PKG_MANAGER="unsupported"
      ;;
  esac
  printf "%bPackage Manager:%b %s\n" "$GREEN" "$NC" "$PKG_MANAGER"

  # Find firewalls installed on the system
  FIREWALLS=()

  # firewalld
  if command -v firewall-cmd &>/dev/null; then
    FIREWALLS+=("firewalld")
  fi

  # ufw
  if command -v ufw &>/dev/null; then
    FIREWALLS+=("ufw")
  fi

  # nftables
  if command -v nft &>/dev/null; then
    FIREWALLS+=("nftables")
  fi

  # iptables
  if command -v iptables &>/dev/null; then
    FIREWALLS+=("iptables")
  fi

  local firewall
  printf "%bInstalled Firewalls: %b" "$GREEN" "$NC"
  for firewall in "${FIREWALLS[@]}"; do
    printf "%b%s%b " "$RED" "$firewall" "$NC"
  done
  printf "\n"

  print_status message info "Checking which services are enabled"
  # Check if commands are present, and/or if their services are enabled
  case "$DISTRO" in
    ubuntu | debian | sles | opensuse* | suse)
      if systemctl is-active --quiet apparmor; then
        printf "%bapparmor.service%b: %brunning%b\n" \
          "$YELLOW" "$NC" "$GREEN" "$NC"
      else
        printf "%bapparmor.service%b: %bnot running%b\n" \
          "$YELLOW" "$NC" "$GREEN" "$NC"
      fi
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      if [[ ! -e /sys/fs/selinux/enforce ]]; then
        printf "%bSELinux%b: %bnot enabled%b\n" \
          "$YELLOW" "$NC" "$RED" "$NC"
      elif [[ $(cat /sys/fs/selinux/enforce) -eq 1 ]]; then
        printf "%bSELinux%b: %benforcing%b\n" \
          "$YELLOW" "$NC" "$GREEN" "$NC"
      else
        printf "%bSELinux%b: %bnot enforcing%b\n" \
          "$YELLOW" "$NC" "$RED" "$NC"
      fi
      ;;
  esac

  if systemctl is-active --quiet systemd-journald; then
    printf "%bsystemd-journald.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
  else
    printf "%bsystemd-journald.service%b: %bnot running%b\n" \
      "$YELLOW" "$NC" "$RED" "$NC"
  fi

  local journal_upload_running="false"
  local rsyslog_running="false"
  if systemctl is-active --quiet systemd-journal-upload; then
    printf "%bsystemd-journal-upload.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
    journal_upload_running="true"
  else
    printf "%bsystemd-journal-upload.service%b: %bnot running%b\n" \
      "$YELLOW" "$NC" "$RED" "$NC"
  fi

  if systemctl is-active --quiet rsyslog; then
    printf "%brsyslog.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
    rsyslog_running="true"
  else
    printf "%brsyslog.service%b: %bnot running%b\n" \
      "$YELLOW" "$NC" "$RED" "$NC"
  fi

  if [[ "$journal_upload_running" == "true" && "$rsyslog_running" == "true" ]]; then
    print_status message warn "Multiple remote logging services running"
  elif [[ "$journal_upload_running" == "false" && "$rsyslog_running" == "false" ]]; then
    print_status message warn "No remote logging services found running"
  fi

  if systemctl is-active --quiet auditd; then
    printf "%bauditd.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
  else
    printf "%bauditd.service%b: %bnot running%b\n" \
      "$YELLOW" "$NC" "$RED" "$NC"
  fi

  if systemctl is-active --quiet dailyaidecheck.timer; then
    printf "%bdailyaidecheck.timer%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
  else
    printf "%bdailyaidecheck.timer%b: %bnot running%b\n" \
      "$YELLOW" "$NC" "$RED" "$NC"
  fi

  local chrony_running="false"
  local timesyncd_running="false"
  if systemctl is-active --quiet systemd-timesyncd; then
    printf "%bsystemd-timesyncd.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
    chrony_running="true"
  fi
  if systemctl is-active --quiet chrony; then
    printf "%bchrony.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
    timesyncd_running="true"
  fi

  if [[ "$chrony_running" == "true" && "$timesyncd_running" == "true" ]]; then
    print_status message alert "Multiple NTP clients running"
  elif [[ "$chrony_running" == "false" && "$timesyncd_running" == "false" ]]; then
    print_status message alert "No NTP clients found running"
  fi

  if systemctl is-active --quiet cron &>/dev/null; then
    printf "%bcron.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
  elif systemctl is-active --quiet crond &>/dev/null; then
    printf "%bcrond.service%b: %brunning%b\n" \
      "$YELLOW" "$NC" "$GREEN" "$NC"
  else
    print_status message alert "cron service is not running"
  fi

  # TODO(michael): Add check for su
  print_status message info "Checking sudo configuration" "(/etc/sudoers)"
  if ! command -v sudo &>/dev/null; then
    print_status not_installed alert "sudo"
  else
    if ! grep -qrPi '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers*; then
      print_status message_object alert option \
        "Not set:" "Defaults use_pty"
    fi
    if ! grep -qrPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers*; then
      print_status message alert \
        "No custom sudo log file configured"
    fi
    if grep -qrE "^[^#].*!authenticate" /etc/sudoers*; then
      print_status message alert \
        "sudo reauthentication not required"
    fi
  fi

  print_status message info "Checking user and group configurations"
  # Check for duplicate UIDs/GIDs and users/groups,
  # as well as users with passwords
  # CIS Ubuntu 5.4.2 and 7.2
  mapfile -t DUPLICATE_UIDS < <(
    awk -F: '{ print $3 }' /etc/passwd | sort | uniq -d
  )
  mapfile -t DUPLICATE_PRIMARY_GIDS < <(
    awk -F: '($4 != 65534) { print $4 }' /etc/passwd | sort | uniq -d
  )
  mapfile -t DUPLICATE_USERNAMES < <(
    awk -F: '{ print $1 }' /etc/passwd | sort | uniq -d
  )
  mapfile -t DUPLICATE_GIDS < <(
    awk -F: '{ print $3 }' /etc/group | sort | uniq -d
  )
  mapfile -t DUPLICATE_GROUP_NAMES < <(
    awk -F: '{ print $1 }' /etc/group | sort | uniq -d
  )

  if [[ "${#DUPLICATE_UIDS[@]}" -gt 0 ]]; then
    print_status message warn "Duplicate UIDs found"
    local uid=""
    for uid in "${DUPLICATE_UIDS[@]}"; do
      if [[ "$uid" -eq 0 ]]; then
        print_status duplicate_found_in alert "UID 0" "/etc/passwd"
      fi
      awk -F: -v uid="$uid" \
        '($3 == uid) { print "User:", $1, "| UID:", $3 }' \
        /etc/passwd
    done
  fi
  if [[ "${#DUPLICATE_PRIMARY_GIDS[@]}" -gt 0 ]]; then
    print_status message warn "Some users share the same primary GID"
    local pgid=""
    for pgid in "${DUPLICATE_PRIMARY_GIDS[@]}"; do
      if [[ "$pgid" -eq 0 ]]; then
        print_status duplicate_found_in alert \
          "Primary GID 0" "/etc/passwd"
      fi
      awk -F: -v pgid="$pgid" \
        '($4 == pgid) { print "User:", $1, "| GID:", $4 }' \
        /etc/passwd
    done
  fi
  if [[ "${#DUPLICATE_USERNAMES[@]}" -gt 0 ]]; then
    print_status message warn "Duplicate usernames found"
    local username=""
    for username in "${DUPLICATE_USERNAMES[@]}"; do
      if [[ "$username" = "root" ]]; then
        print_status duplicate_found_in alert "root" "/etc/passwd"
      fi
      awk -F: -v username="$username" \
        '($1 == username) { print $1 ":" $2 ":" $3 ":" $4 ":" $5 ":" $6 ":" $7 }' \
        /etc/passwd
    done
  fi
  if [[ "${#DUPLICATE_GIDS[@]}" -gt 0 ]]; then
    print_status message warn "Duplicate GIDs found"
    local gid=""
    for gid in "${DUPLICATE_GIDS[@]}"; do
      if [[ "$gid" -eq 0 ]]; then
        print_status duplicate_found_in alert "GID 0" "/etc/group"
      fi
      awk -F: -v gid="$gid" \
        '($3 == gid) { print "Group:", $1, "| GID:", $3 }' \
        /etc/group
    done
  fi
  if [[ "${#DUPLICATE_GROUP_NAMES[@]}" -gt 0 ]]; then
    print_status message warn "Duplicate group names found"
    local group_name=""
    for group_name in "${DUPLICATE_GROUP_NAMES[@]}"; do
      if [[ "$group_name" = "root" ]]; then
        print_status duplicate_found_in alert "root" "/etc/group"
      fi
      awk -F: -v group_name="$group_name" \
        '($1 == group_name) { print $1 ":" $2 ":" $3 }' /etc/group
    done
  fi

  # Checks if users are in the shadow group
  if [[ "$DISTRO" =~ ^(debian|ubuntu|sles|opensuse.*|suse)$ ]]; then
    SHADOW_GID=$(awk -F: '($1 == "shadow")  { print $3 }' /etc/group)
    mapfile -t SHADOW_PGID < <(
      awk -F: -v SHADOW_GID="$SHADOW_GID" \
        '($4 == SHADOW_GID) { print $1 }' /etc/passwd
    )
    mapfile -t SHADOW_GROUP_MEMBER < <(
      awk -F: '($1 == "shadow" && $4 != "")  { print $4 }' /etc/group
    )
    if [[ "${#SHADOW_PGID[@]}" -gt 0 ]]; then
      print_status found_in alert \
        "Users with Primary GID of shadow group" "/etc/passwd"
      local user
      for user in "${SHADOW_PGID[@]}"; do
        printf "%s\n" "$user"
      done
    fi
    if [[ "${#SHADOW_GROUP_MEMBER[@]}" -gt 0 ]]; then
      print_status found_in alert \
        "Users apart of shadow group" "/etc/group"
      local user
      for user in "${SHADOW_GROUP_MEMBER[@]}"; do
        printf "%s\n" "$user"
      done
    fi
  fi

  # This keeps a portion of the password section,
  # just so the user can confirm that the script isnt lying
  mapfile -t SHADOW_USERS_REDACTED < <(
    awk -F: -v OFS=":" \
      '
      ($2 != "" && $2 !~ /^[!*]/) {
        print $1, substr($2, 1, 10) "...", $3, $4, $5, $6, $7, $8, $9
      }
      ' \
      /etc/shadow
  )
  local user
  printf "%bUsers with password configured in%b %b/etc/shadow%b%b:%b\n" \
    "$YELLOW" "$NC" \
    "$CYAN" "$NC" \
    "$YELLOW" "$NC"
  for user in "${SHADOW_USERS_REDACTED[@]}"; do
    printf "%s\n" "$user"
  done
}
