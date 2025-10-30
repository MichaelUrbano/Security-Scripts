#!/bin/bash

# CIS Ubuntu: 1.1.2
# We only want to do /tmp and /dev/shm, any related to /home or /var are out of scope
configure_partitions() {
  local tmp_noexec="false"
  #echo "tmpfs /tmp tmpfs defaults,nosuid,nodev 0 0" >> /etc/fstab
  #echo "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab
  if grep -qE \
    '^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/tmp[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+' \
    /etc/fstab; then
    local -a options
    local option
    mapfile -t options < <(
      sed -nE \
        's|^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/tmp[[:blank:]]+[^[:space:]]+[[:blank:]]+([^[:space:]]+)[[:blank:]]*[0-9]*[[:blank:]]*[0-9]*|\1|p' \
        /etc/fstab \
        | tr "," "\n"
    )
    local nodev="false"
    local nosuid="false"
    local noexec="false"
    for option in "${options[@]}"; do
      if [[ "$option" == "nodev" ]]; then
        nodev="true"
        continue
      fi
      if [[ "$option" == "nosuid" ]]; then
        nosuid="true"
        continue
      fi
      if [[ "$option" == "noexec" ]]; then
        noexec="true"
        continue
      fi
    done
    if [[ "$nodev" == "false" ]]; then
      sed -iE \
        's|(^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/tmp[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+)([[:blank:]]*[0-9]*[[:blank:]]*[0-9]*)|\1,nodev\2|' \
        /etc/fstab
    fi
    if [[ "$nosuid" == "false" ]]; then
      sed -iE \
        's|(^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/tmp[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+)([[:blank:]]*[0-9]*[[:blank:]]*[0-9]*)|\1,nosuid\2|' \
        /etc/fstab
    fi
    if [[ "$noexec" == "false" && "$tmp_noexec" == "true" ]]; then
      sed -iE \
        's|(^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/tmp[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+)([[:blank:]]*[0-9]*[[:blank:]]*[0-9]*)|\1,noexec\2|' \
        /etc/fstab
    fi
  else
    echo "tmpfs /tmp tmpfs defaults,nodev,nosuid 0 0" >>/etc/fstab
    if [[ "$tmp_noexec" == "true" ]]; then
      sed -iE \
        's|(^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/tmp[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+)([[:blank:]]*[0-9]*[[:blank:]]*[0-9]*)|\1,noexec\2|' \
        /etc/fstab
    fi
  fi

  if grep -qE '^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/dev\/shm[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+' /etc/fstab; then
    local -a options
    local option
    mapfile -t options < <(
      sed -nE \
        's|^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/dev\/shm[[:blank:]]+[^[:space:]]+[[:blank:]]+([^[:space:]]+)[[:blank:]]*[0-9]*[[:blank:]]*[0-9]*|\1|p' \
        /etc/fstab \
        | tr "," "\n"
    )
    local nodev="false"
    local nosuid="false"
    local noexec="false"
    for option in "${options[@]}"; do
      if [[ "$option" == "nodev" ]]; then
        nodev="true"
        continue
      fi
      if [[ "$option" == "nosuid" ]]; then
        nosuid="true"
        continue
      fi
      if [[ "$option" == "noexec" ]]; then
        noexec="true"
        continue
      fi
    done
    if [[ "$nodev" == "false" ]]; then
      sed -iE 's|(^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/dev\/shm[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+)([[:blank:]]*[0-9]*[[:blank:]]*[0-9]*)|\1,nodev\2|' \
        /etc/fstab
    fi
    if [[ "$nosuid" == "false" ]]; then
      sed -iE 's|(^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/dev\/shm[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+)([[:blank:]]*[0-9]*[[:blank:]]*[0-9]*)|\1,nosuid\2|' \
        /etc/fstab
    fi
    if [[ "$noexec" == "false" ]]; then
      sed -iE 's|(^[[:blank:]]*[^#[[:blank:]]][^[[:blank:]]]*[^[:space:]]+[[:blank:]]+\/dev\/shm[[:blank:]]+[^[:space:]]+[[:blank:]]+[^[:space:]]+)([[:blank:]]*[0-9]*[[:blank:]]*[0-9]*)|\1,noexec\2|' \
        /etc/fstab
    fi
  else
    echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >>/etc/fstab
  fi
}

# CIS Ubuntu and RHEL
# 6.1.1.2 is for journald and must be done through
# cp /usr/lib/tmpfiles.d/systemd.conf /etc/tmpfiles.d/systemd.conf,
# not yet implemented
# 6.1.3.4/6.2.3.4 is for rsyslog, not yet implemented
# 6.1.4.1/6.2.4.1 is for /var/log, and must be implemented through a loop,
# not yet implemented
# 6.3.4 is for auditd, and is not yet implemented
# 7.1.11 is world writeable files,
# which need to not exist or have the sticky bit set
# 7.1.12 is files with no user/group,
# which should not exist, or should be assigned a user/group
# 7.1.13 is ensure SUID and SGID files are reviewed,
# which is done via linpeas.sh
configure_permissions() {
  # Format for the permissions is the following:
  # path:type:owner:group:mode
  # In the 2nd field, f is file and d is directory
  local -a permissions=(
    "/boot/grub/grub.cfg:f:root:root:0600" # 1.4.2
    "/etc/motd:f:root:root:0644"           # 1.6.4
    "/etc/issue:f:root:root:0644"          # 1.6.5
    "/etc/issue.net:f:root:root:0644"      # 1.6.6
    "/etc/crontab:f:root:root:0600"        # 2.4.1.2
    "/etc/cron.hourly:d:root:root:0600"    # 2.4.1.3
    "/etc/cron.daily:d:root:root:0600"     # 2.4.1.4
    "/etc/cron.weekly:d:root:root:0600"    # 2.4.1.5
    "/etc/cron.monthly:d:root:root:0600"   # 2.4.1.6
    "/etc/cron.d:d:root:root:0600"         # 2.4.1.7
    "/etc/cron.yearly:d:root:root:0600"
    "/etc/at.allow:f:root:daemon:0640"           # 2.4.2.1
    "/etc/at.deny:f:root:daemon:0640"            # 2.4.2.1
    "/etc/passwd:f:root:root:0644"               # 7.1.1
    "/etc/passwd-:f:root:root:0644"              # 7.1.2
    "/etc/group:f:root:root:0644"                # 7.1.3
    "/etc/group-:f:root:root:0644"               # 7.1.4
    "/etc/shells:f:root:root:0644"               # 7.1.9
    "/etc/security/opasswd:f:root:root:0600"     # 7.1.10
    "/etc/security/opasswd.old:f:root:root:0600" # 7.1.10
  )
  local -ar ubuntu_permissions=(
    "/etc/cron.allow:f:root:crontab:0640" # 2.4.1.8
    "/etc/cron.deny:f:root:crontab:0640"  # 2.4.1.8
    "/etc/shadow:f:root:shadow:0640"      # 7.1.5
    "/etc/shadow-:f:root:shadow:0640"     # 7.1.6
    "/etc/gshadow:f:root:shadow:0640"     # 7.1.7
    "/etc/gshadow-:f:root:shadow:0640"    # 7.1.8
  )
  local -ar rhel_permissions=(
    "/etc/cron.allow:f:root:root:0640" # 2.4.1.8
    "/etc/cron.deny:f:root:root:0640"  # 2.4.1.8
    "/etc/shadow:f:root:root:0000"     # 7.1.5
    "/etc/shadow-:f:root:root:0000"    # 7.1.6
    "/etc/gshadow:f:root:root:0000"    # 7.1.7
    "/etc/gshadow-:f:root:root:0000"   # 7.1.8
  )
  # This doesn't check cloud-init.log, localmessages, and waagent.log
  # SSSD, gdm, and gdm3 are also not checked
  # Nor are journal files, and all other log files present
  # Checks for those should eventually be implemented
  # Additionally these permissions will not last if logs are rotated
  # (/etc/logrotate.conf and /etc/logrotate.d)
  # Okay for a competition, not a production system
  # All other files should be owned by root or syslog (usually)
  # Group should be root or adm (usually)
  # Mode should be at least 0640
  # 6.1.4/6.2.4 perms
  local -a log_files=(
    "/var/log/lastlog*:f:root:utmp:0664"
    "/var/log/wtmp*:f:root:utmp:0664"
    "/var/log/btmp*:f:root:utmp:0660"
  )
  local -ar debian_logging=(
    "/var/log/auth.log*:f:root:adm:0640"
    "/var/log/syslog*:f:root:adm:0640"
  )
  local -ar ubuntu_logging=(
    "/var/log/auth.log*:f:syslog:adm:0640"
    "/var/log/syslog*:f:syslog:adm:0640"
  )
  local -ar rhel_logging=(
    "/var/log/secure*:f:root:root:0600"
    "/var/log/messages*:f:root:root:0600"
  )
  local -ar suse_logging=(
    "/var/log/secure*:f:root:root:0640"
    "/var/log/messages*:f:root:root:0640"
  )

  if [[ "$DISTRO" =~ ^(ubuntu|debian|opensuse.*)$ ]]; then
    permissions+=("${ubuntu_permissions[@]}")
  elif [[ "$DISTRO" =~ ^(centos|rocky|almalinux|fedora|rhel|ol)$ ]]; then
    permissions+=("${rhel_permissions[@]}")
  fi

  local permission path type owner group mode
  for permission in "${permissions[@]}"; do
    IFS=':' read -r path type owner group mode <<<"$permission"
    # Does the file/directory exist?
    case "$type" in
      f)
        if [[ ! -f "$path" ]]; then
          print_status not_found warn file "$path"
          permission="" path="" type="" owner="" group="" mode=""
          continue
        fi
        ;;
      d)
        if [[ ! -d "$path" ]]; then
          print_status not_found warn directory "$path"
          permission="" path="" type="" owner="" group="" mode=""
          continue
        fi
        ;;
      *)
        print_status error "Type was not f or d."
        return 1
        ;;
    esac

    chown "${owner}:${group}" "$path" && chmod "$mode" "$path"
    permission="" path="" type="" owner="" group="" mode=""
  done

  local file
  local wildcard_path
  # 6.1.4/6.2.4
  if ! [[ -d /var/log ]]; then
    print_status not_found alert directory "/var/log"
    return 1
  fi
  case "$DISTRO" in
    ubuntu)
      log_files+=( "${ubuntu_logging[@]}" )
      ;;
    debian)
      log_files+=( "${debian_logging[@]}" )
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      log_files+=( "${rhel_logging[@]}" )
      ;;
    opensuse*)
      log_files+=( "${suse_logging[@]}" )
      ;;
    *)
      :
      ;;
  esac

  shopt -s nullglob # So wildcard paths are interpreted safely
  for permission in "${log_files[@]}"; do
    IFS=':' read -r wildcard_path type owner group mode <<<"$permission"
    for file in $wildcard_path; do
      [[ -f "$file" ]] || continue
      chown "${owner}:${group}" "$file" && chmod "$mode" "$file"
    done
  done
  shopt -u nullglob

  # 5.1.1
  if [[ -f /etc/ssh/sshd_config ]]; then
    chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config
  else
    print_status not_found warn file "/etc/ssh/sshd_config"
  fi
  if [[ -d /etc/ssh/sshd_config.d ]]; then
    for file in /etc/ssh/sshd_config.d/*.conf; do
      [ -e "$file" ] || continue
      chown root:root "$file" && chmod 0600 "$file"
    done
  else
    print_status not_found warn directory "/etc/ssh/sshd_config.d"
  fi

  # 5.1.2-3
  case "$DISTRO" in
    ubuntu | debian | fedora | opensuse*)
      if [[ -d /etc/ssh ]]; then
        for file in /etc/ssh/*.pub; do
          [[ -e "$file" ]] || continue
          chown root:root "$file" && chmod 0644 "$file"
        done
        for file in /etc/ssh/*; do
          [[ "$file" =~ key$ ]] || continue
          chown root:root "$file" && chmod 0600 "$file"
        done
      else
        print_status not_found warn directory "/etc/ssh"
      fi
      ;;
    centos | rocky | almalinux | rhel | ol)
      if [[ -d /etc/ssh ]]; then
        for file in /etc/ssh/*.pub; do
          [[ -e "$file" ]] || continue
          chown root:root "$file" && chmod 0644 "$file"
        done
        for file in /etc/ssh/*; do
          [[ "$file" =~ key$ ]] || continue
          chown root:ssh_keys "$file" && chmod 0600 "$file"
        done
      else
        print_status not_found warn directory "/etc/ssh"
      fi
      ;;
  esac
}
