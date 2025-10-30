#!/bin/bash

# Basic tar backup function for /etc, /var/www/html, and /opt 
# to directory specified in env ($BAKDIR), defaults to /usr/sbin/ if unspecified
# Will also try to make deleting or modifying backups a little annoying
# Will put your backups into the child directory <backup_directory>/b4
backup_directories() {
  local backup_directory="${1:-/usr/bin}"
  local backup_subdirectory="${2:-/b4}"
  # Valid directory starting with /, not starting directories
  # with -, is less than 255 characters, and ends without a trailing /
  if [[ ! "$backup_directory" =~ ^(\/[A-Za-z0-9._][A-Za-z0-9._-]{0,254})+$ ]]; then
    print_status message error "Invalid backup directory"
    return 1
  elif [ ! -d "$backup_directory" ]; then
    print_status message error "Backup directory does not exist"
    return 1
  fi
  if [[ ! "$backup_subdirectory" =~ ^(\/[A-Za-z0-9._][A-Za-z0-9._-]{0,254})+$ ]]; then
    print_status message error "Invalid backup directory"
    return 1
  fi
  local backup_path="${backup_directory}${backup_subdirectory}"
  mkdir -p "${backup_path}"
  chmod 1755 "${backup_path}"
  local flag

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
