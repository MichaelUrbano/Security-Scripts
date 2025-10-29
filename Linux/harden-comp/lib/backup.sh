# Basic tar backup function for /etc, /var/www/html, and /opt 
# to directory specified in env ($BAKDIR), defaults to /usr/sbin/ if unspecified
# Will also try to make deleting or modifying backups a little annoying
# Will put your backups into the child directory <backup_directory>/b4
backup_directories() {
  local backup_directory="${BAKDIR:-/usr/sbin}"
  if [ ! -d "$backup_directory" ]; then
    print_status message error "Backup directory does not exist"
    return 1
  fi
  local backup_path="${backup_directory}/b4"
  mkdir -p "${backup_path}"
  chmod 1755 "${backup_path}"
  local flag=""

  if [ -d "/etc" ]; then
    echo -e "Backing up ${YELLOW}/etc${NC}"
    local etc_backup=""
    etc_backup="${backup_path}/ettc-$(date +%b-%d-%H.%M.%S)"
    tar -cf "$etc_backup" /etc
    for flag in u a i; do
      chattr +"$flag" "$etc_backup" &>/dev/null || true
    done
  fi
  if [ -d "/var/www/html" ]; then
    echo -e "Backing up ${YELLOW}/var/www/html${NC}"
    local html_backup=""
    html_backup="${backup_path}/httml-$(date +%b-%d-%H.%M.%S)"
    tar -cf "$html_backup" /var/www/html &>/dev/null || true
    for flag in u a i; do
      chattr +"$flag" "$html_backup" &>/dev/null || true
    done
  fi
  if [ -d "/opt" ]; then
    echo -e "Backing up ${YELLOW}/opt${NC}"
    local opt_backup=""
    opt_backup="${backup_path}/oppt-$(date +%b-%d-%H.%M.%S)"
    tar -cf "$opt_backup" /opt &>/dev/null || true
    for flag in u a i; do
      chattr +"$flag" "$opt_backup" &>/dev/null || true
    done
  fi
  echo -e "Done. You can find your backups at ${YELLOW}${backup_path}${NC}"
}

# Performs a backup of given firewall, putting the backups into /srv/backups
# It also inserts into the associative array FW_BACKUPS,
# containing the path of each backup as the key,
# and the name of the original file as the value
# These are meant to be more of a "rollback" than an entire backup
# They aren't very well protected in comparison to backups by backup_directories
# May serve as a good IoC if these files suddenly vanish
# backup_firewall "firewalld|ufw|nftables|iptables" "backup_name"
backup_firewall() {
  mkdir -p /srv/backups
  FW_BACKUPS=()
  case "$1" in
    firewalld)
      local backup_name
      local zone
      local -a zones
      if [[ -d /etc/firewalld/zones ]]; then
        {
          mapfile -t zones < <(ls /etc/firewalld/zones)
          for zone in "${zones[@]}"; do
            backup_name="/srv/backups/${2}-$(date +%b-%d-%H.%M.%S)-${zone}"
            cp "/etc/firewalld/zones/${zone}" "$backup_name" \
              && chmod 0600 "$backup_name"
            FW_BACKUPS["$backup_name"]="/etc/firewalld/zones/${zone}"
          done
        } || {
          print_status message error "Firewall backup failed"
          return 1
        }
      else
        print_status not_found warn directory "/etc/firewalld/zones"
      fi

      return 0
      ;;
    ufw)
      local backup_name
      if [[ -f /etc/ufw/user.rules ]]; then
        {
          backup_name="/srv/backups/${2}-$(date +%b-%d-%H.%M.%S)-user.rules"
          cp "/etc/ufw/user.rules" "$backup_name"
          FW_BACKUPS["$backup_name"]="/etc/ufw/user.rules"
        } || {
          print_status message error "Firewall backup failed"
          return 1
        }
      else
        print_status not_found warn file "/etc/ufw/user.rules"
      fi

      if [[ -f /etc/ufw/user6.rules ]]; then
        {
          backup_name="/srv/backups/${2}-$(date +%b-%d-%H.%M.%S)-user6.rules"
          cp "/etc/ufw/user6.rules" "$backup_name"
          FW_BACKUPS["$backup_name"]="/etc/ufw/user6.rules"
        } || {
          print_status message error "Firewall backup failed"
          return 1
        }
      else
        print_status not_found warn file "/etc/ufw/user6.rules"
      fi

      return 0
      ;;
    nftables)
      local backup_name
      if [[ -f "/etc/nftables.conf" ]]; then
        {
          backup_name="/srv/backups/${2}-$(date +%b-%d-%H.%M.%S)-nftables.conf"
          cp "/etc/nftables.conf" "$backup_name"
          FW_BACKUPS["$backup_name"]="/etc/nftables.conf"
        } || {
          print_status message error "Firewall backup failed"
          return 1
        }
      elif [[ -f "/etc/sysconfig/nftables.conf" ]]; then
        {
          backup_name="/srv/backups/${2}-$(date +%b-%d-%H.%M.%S)-nftables.conf"
          cp "/etc/sysconfig/nftables.conf" "$backup_name"
          FW_BACKUPS["$backup_name"]="/etc/sysconfig/nftables.conf"
        } || {
          print_status message error "Firewall backup failed"
          return 1
        }
      else
        print_status message warn "No files found for firewall backup"
      fi

      return 0
      ;;
    iptables)
      local backup_name
      if [[ -f "/etc/iptables/rules.v4" ]]; then
        {
          backup_name="/srv/backups/${2}-$(date +%b-%d-%H.%M.%S)-rules.v4"
          cp "/etc/iptables/rules.v4" "$backup_name"
          FW_BACKUPS["$backup_name"]="/etc/iptables/rules.v4"
        } || {
          print_status message error "Firewall backup failed"
          return 1
        }
      else
        print_status not_found warn file "/etc/iptables/rules.v4"
      fi

      if [[ -f "/etc/iptables/rules.v6" ]]; then
        {
          backup_name="/srv/backups/${2}-$(date +%b-%d-%H.%M.%S)-rules.v6"
          cp "/etc/iptables/rules.v6" "$backup_name"
          FW_BACKUPS["$backup_name"]="/etc/iptables/rules.v6"
        } || {
          print_status message error "Firewall backup failed"
          return 1
        }
      else
        print_status not_found warn file "/etc/iptables/rules.v6"
      fi

      return 0
      ;;
    *)
      print_status message error "Unrecognized firewall"
      return 1
      ;;
  esac
}

restore_firewall() {
  if [[ ! -d "/srv/backups" ]]; then
    print_status not_found error directory "/srv/backups"
    return 1
  fi

  if [[ "${#FW_BACKUPS[@]}" -le 0 ]]; then
    print_status message error "No backups listed"
    return 1
  fi

  local path
  for path in "${!FW_BACKUPS[@]}"; do
    cp "$path" "${FW_BACKUPS["$path"]}" || {
      print_status message error "Failed to restore ${path}"
      return 1
    }
  done
}