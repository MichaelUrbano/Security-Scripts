#!/usr/bin/env bash

# TODO: Do not perform backup if directory is bigger than threshold set
# (Default is 500, a command line option should be added to tweak this)

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
        tar -cf "${backup_name}.tar" "${directory}" &>/dev/null || true
        extension=".tar"
      else
        tar -czf "${backup_name}.tgz" "${directory}" &>/dev/null || true
        extension=".tgz"
      fi
      for flag in u a i; do
        chattr +"$flag" "${backup_name}${extension}" &>/dev/null || true
      done
    fi
  done

  print_status message_object success directory "Completed backups to" "$backup_path"
}

# Not using this since its less "proper" to pipe ps to grep,
# but if for some reason the other breaks, this should still be functional
# ps -eaf --forest | \
#   grep -vE "([0-9]([[:blank:]]|\|)*\\\_[[:blank:]]\[.*\]|\[kthreadd\])$" | \
#   less -S
pscf() {
  ps -fp $(pgrep -P2 -v -d,) --forest | \
    sed -E "s|\/nix\/store\/.*\/|nixstor\:\/|g" | \
    grep -v "ps -p [0-9]*" | \
    less -S
}

# Should provide a "simplified" output, searching for "suspicious" processes
pscs() {
  ps -p $(pgrep -P2 -v -d,) -o euser,pid,ppid,tty,args | \
    sed -E "s|\/nix\/store\/.*\/|nixstor\:\/|g" | \
    grep -v "ps -p [0-9]*" | \
    grep -E "bash|sh|rbash|python|php|ssh|httpd|apache|nginx" | \
    less -S
}

# Just excludes loopback addresses
ssc() {
  ss -tulpn | grep -v -e "127.0.0.1" -e "\[\:\:1\]" | less -S
}