#!/usr/bin/env bash

# Basic tar backup function for /etc, /var/www/html, and /opt 
# to directory specified with -b, defaults to /usr/sbin if unspecified
# Will put your backups into the child directory specified with -B,
# defaults to /b4 if unspecified
# Will also try to make deleting or modifying backups a little annoying
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
  local backup_name
  local directory
  local extension
  local -Ar directories=(
    ["/etc"]="/ettc-"
    ["/var/www/html"]="/httml-"
    ["/opt"]="/oppt-"
  )

  for directory in "${!directories[@]}"; do
    if [[ -d "$directory" ]]; then
      print_status message_object info directory \
        "Performing backup on" "$directory"
      backup_name="${backup_path}${directories[$directory]}$(date +%b-%d-%H.%M.%S)"
      if [[ "$ARG_COMPRESS" == "disabled" ]]; then
        tar -cf "${backup_name}.tar" "${directory}" &> /dev/null || true
        extension=".tar"
      else
        tar -czf "${backup_name}.tgz" "${directory}" &> /dev/null || true
        extension=".tgz"
      fi
      for flag in u a i; do
        chattr +"$flag" "${backup_name}${extension}" &> /dev/null || true
      done
    fi
  done

  print_status message_object success directory "Completed backups to" "$backup_path"
}
