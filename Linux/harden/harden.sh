#!/usr/bin/env bash
# shellcheck source=/dev/null
# shellcheck disable=SC2034

# Want to get close to Google's styleguide?
# Run shfmt -i 2 -ci -bn

# Check ./lib/not-yet-implemented for TODOs

set -euo pipefail
set +H

SCRIPT_VERSION="unknown-build"
ARG_DIRECTORY=""
ARG_SUBDIRECTORY=""
ARG_DISTRO=""
ARG_FW=""
ARG_PM=""
ARG_VER=""
ARG_CLEAR="enabled"
ARG_QUICK="disabled"
ARG_BACKUP="disabled"
ARG_COMPRESS="enabled"
SKIP_MAIN="false"
SKIP_PKG_CHK="false"

if [[ "$SCRIPT_VERSION" == "unknown-build" ]] && command -v git describe &>/dev/null; then
  SCRIPT_VERSION=$(git describe --tags --always --dirty)
fi

# Set ANSI Escape Code variables for different colors in the terminal
readonly RED='\033[0;31m'      # For ERROR or Firewalls
readonly GREEN='\033[0;32m'    # For SUCCESS
readonly YELLOW='\033[0;33m'   # For WARN, Commands, or Options
readonly BLUE='\033[0;34m'     # For INFO
readonly MAGENTA='\033[0;35m'  # For Directories
readonly CYAN='\033[0;36m'     # For Files
readonly BOLD='\033[1m'        # At your own discretion
readonly NC='\033[0m'          # Clears colors/bolding
readonly EC="${RED}${BOLD}"    # [ERROR]
readonly WC="${YELLOW}${BOLD}" # [WARN]
readonly IC="${BLUE}${BOLD}"   # [INFO]
readonly SC="${GREEN}${BOLD}"  # [SUCCESS]
readonly UC="\033[1;4;43;31m"  # [UNKNOWN]

# Set the pseudo-prompt for the script
PSS="harden"
PSE=">"
PSC="${GREEN}${BOLD}"

print_prompt() {
  SUBPROMPT=${1:-""}
  printf "%b%s%s%s%b" "${PSC}" "${PSS}" "$SUBPROMPT" "${PSE}" "${NC} "
}

# List of Linux Distributions IDs supported by the script
declare -ar SUPPORTED_DISTROS=(
  "ubuntu"
  "debian"
  "sles"
  "opensuse"
  "suse"
  "centos" 
  "rocky" 
  "almalinux" 
  "ol" 
  "fedora" 
  "rhel"
)

# Regex containing Linux distributions supported by the script
readonly REGEX_ALL_DISTROS='^(ubuntu|debian|sles|opensuse.*|suse|centos|rocky|almalinux|ol|fedora|rhel)$'
readonly REGEX_DEB_DISTROS='^(ubuntu|debian)$'
readonly REGEX_SUSE_DISTROS='^(sles|opensuse.*|suse)$'
readonly REGEX_RPM_DISTROS='^(centos|rocky|almalinux|ol|fedora|rhel)$'

# For testing purposes, will execute before init() within main()
do_before() {
  return 0
}

# For testing purposes, will execute after init() within main()
do_after() {
  return 0
}

# TODO: check if version of bash is at least 4.0

check_root() {
  if [ "$EUID" -ne 0 ]; then
    printf \
      "%bThis script must be run as%b %broot%b%b, or with%b %bsudo%b%b.%b\n" \
      "$YELLOW" "$NC" \
      "${RED}${BOLD}" "$NC" \
      "$YELLOW" "$NC" \
      "${RED}${BOLD}" "$NC" \
      "$YELLOW" "$NC"
    exit 1
  fi
}

override() {
  if [[ -n "$ARG_DISTRO" ]]; then
    DISTRO="$ARG_DISTRO"
    print_status message_object alert option \
      "Overriding distribution ID:" "$DISTRO"
  fi
  if [[ -n "$ARG_VER" ]]; then
    VER="$ARG_VER"
    print_status message_object alert option \
      "Overriding distribution version:" "$VER"
  fi
  if [[ -n "$ARG_PM" ]]; then
    PKG_MANAGER="$ARG_PM"
    print_status message_object alert option \
      "Overriding package manager:" "$PKG_MANAGER"
  fi
  if [[ -n "$ARG_FW" ]]; then
    FIREWALLS=("$ARG_FW")
    print_status message_object alert option \
      "Overriding firewall:" "${FIREWALLS[0]}"
  fi
  if [[ -n "$ARG_DIRECTORY" ]]; then
    print_status message_object info directory \
      "Backup directory set:" "$ARG_DIRECTORY"
  fi
  if [[ -n "$ARG_SUBDIRECTORY" ]]; then
    print_status message_object info directory \
      "Backup subdirectory set:" "$ARG_SUBDIRECTORY"
  fi
}

print_version() {
  cat << EOF
harden.sh ${SCRIPT_VERSION} from Security Scripts
Copyright (C) 2025 - 2026 Michael Urbano
Licensed under the BSD 3-Clause License
See: https://opensource.org/licenses/BSD-3-Clause

EOF
}

print_help() {
  cat << EOF
Usage: sudo $0 [OPTIONS]...
Hardening and utility script for competitions

OPTIONS:
  -b, --backup DIRECTORY    send backups to/check for backups in DIRECTORY/b4
                              default value is /usr/bin
  -B, --backup-subdirectory DIRECTORY
                            change backup subdirectory
                              default value is /b4
  -c, --no-clear            disable screen clearing
  -C, --no-compress         backups will not be compressed
  -d, --distro DIST         override distribution
  -e, --no-errfail          will set +e on the script, preventing the script
                              from exiting on any non-zero status (DANGEROUS)
  -f, --firewall FW         override firewall
  -i, --init                show information from init() function, then exit
  -p, --pkg-manager PM      override package manager
  -P, --skip-pkg-chk        skips check_installed_packages() inside of main()
  -q, --run-quick           run all options under Quick, then exit
  -r, --run-backup          will run backup, then exit
  -s, --skip-main           skips main() function
  -V, --distro-version VER  override distribution version
  -x, --xtrace              will set -x on the script, for debugging
  -h, --help                display this help and exit
      --version             output version information and exit

EXAMPLES:
  Set full backup directory as /srv/backups/b4
  sudo $0 --backup /srv/backups

  Set backup directory as /srv/backups and backup subdirectory as /alt
  sudo $0 -b /srv/backups -B /alt

  Set backup directory as /backups and backup subdirectory as /alt and set -x
  sudo $0 --backup /backups -B /alt -x

  Set full backup directory as /usr/bin/alt and override firewall to nftables
  sudo $0 --backup-subdir /alt -f nftables

  Set backup directory as /backups and backup subdirectory as /net and skip main
  sudo $0 -b /backups --backup-subdir /net -s

  Override distribution to fedora, package manager to yum, and firewall to ufw
  sudo $0 -d fedora -p yum -f ufw

Short options or long options can be used exclusively, or combined,
both forms are considered valid by the script.

The DIST argument can be ubuntu, debian, sles, opensuse, suse, centos, rocky, almalinux,
fedora, rhel, ol, or arch.
Otherwise the script will attempt to automatically determine what the system's
distribution is.

The FW argument can be firewalld, ufw, nftables, or iptables.
Otherwise the script will attempt to automatically determine what firewall the
system is using.

The PM argument can be apt, dnf, yum, zypper, or pacman.
Otherwise the script will attempt to automatically determine what
package manager the system is using.

The VER argument is an integer or float, which must be positive, and
greater than or equal to 0.
Otherwise the script will attempt to automatically determine what your
distribution version is.

Exit status:
 0  if OK,
 1  if any problems occur.

harden.sh ${SCRIPT_VERSION}
from Security Scripts
For more information, please visit the GitHub page.
<https://github.com/MichaelUrbano/Security-Scripts>.
Report bugs and issues on the Issues page.
Report vulnerabilities directly to git@michaelurbano.com

EOF
}

SHORT_OPTIONS="hb:B:cd:ef:ip:PqrsV:xh"
LONG_OPTIONS="backup:,backup-subdirectory:,no-clear,no-compress,distro:,no-errfail,firewall:,init,pkg-manager:,skip-pkg-chk,run-quick,run-backup,skip-main,distro-version:,xtrace,help,version"
OPTIONS=$(
  getopt -o "$SHORT_OPTIONS" \
    -l "$LONG_OPTIONS" \
    -n "$0" -- "$@"
)
eval set -- "$OPTIONS"

# Check for OPTIONS passed
# TODO: Replace this with getopts, as well as use compgen, compopt, and complete
while true; do
  case "$1" in
    -h | --help)
      print_help
      exit 0
      ;;
    --version)
      print_version
      exit 0
      ;;
    -b | --backup)
      if [[ -z "$2" && "$2" == -* ]]; then
        printf "Error: DIRECTORY must be provided\n"
        exit 1
      # Valid directory starting with /, not starting directories
      # with -, is less than 255 characters, and ends without a trailing /
      elif [[ ! "$2" =~ ^(\/[A-Za-z0-9._][A-Za-z0-9._-]{0,254})+$ ]]; then
        printf "Error: DIRECTORY must start with / and not end with /\n"
        exit 1
      elif [[ ! -d "$2" ]]; then
        printf "Error: %s not found\n" "$2"
        exit 1
      else
        ARG_DIRECTORY="$2"
      fi
      shift 2
      ;;
    -B | --backup-subdirectory)
      if [[ -z "$2" && "$2" == -* ]]; then
        printf "Error: DIRECTORY must be provided\n"
        exit 1
      elif [[ "$2" =~ \/\.{1,2} ]]; then
        printf "Error: DIRECTORY cannot be /. or /..\n"
        exit 1
      elif [[ ! "$2" =~ ^(\/[A-Za-z0-9._][A-Za-z0-9._-]{0,254})+$ ]]; then
        printf "Error: DIRECTORY must start with / and not end with /\n"
        exit 1
      else
        ARG_SUBDIRECTORY="$2"
      fi
      shift 2
      ;;
    -c | --no-clear)
      ARG_CLEAR="disabled"
      shift
      ;;
    -d | --distro)
      ARG_DISTRO="${2:-unknown}"
      shift 2 # || printf "Error: DIST cannot be empty\n"; exit 1
      ;;
    -e | --no-errfail)
      set +e
      shift
      ;;
    -f | --firewall)
      ARG_FW="${2:-unknown}"
      shift 2 # || printf "Error: FW cannot be empty\n"; exit 1
      ;;
    -i | --init)
      check_root
      . ./lib/status.sh
      . ./lib/initialization.sh
      init
      exit 0
      ;;
    -p | --pkg-manager)
      ARG_PM="${2:-unknown}"
      shift 2 # || printf "Error: PM cannot be empty\n"; exit 1
      ;;
    -P | --skip-pkg-chk)
      SKIP_PKG_CHK="true"
      shift
      ;;
    -q | --run-quick)
      ARG_QUICK="enabled"
      shift
      ;;
    -r | --run-backup)
      ARG_BACKUP="enabled"
      shift
      ;;
    -s | --skip-main)
      SKIP_MAIN="true"
      shift
      ;;
    -V | --distro-version)
      ARG_VER="${2:-unknown}"
      shift 2 # || printf "Error: VER cannot be empty\n"; exit 1
      ;;
    -x | --xtrace)
      set -x
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      printf "Usage: sudo %s [OPTIONS]...\n" "$0"
      printf "Try '%s -h' for more information.\n" "$0"
      exit 1
  esac
done

# Now that the options have been passed and checked, we can check for root
check_root

if [[ "$ARG_BACKUP" == "enabled" ]]; then
  . ./lib/status.sh
  . ./lib/utility.sh
  backup_directories "$ARG_DIRECTORY" "$ARG_SUBDIRECTORY" \
  || print_status unsuccessful_function error \
    "backup_directories"
  exit 0
fi
if [[ "$ARG_QUICK" == "enabled" ]]; then
  . ./lib/initialization.sh
  . ./lib/utility.sh
  . ./lib/status.sh
  . ./lib/kernel.sh
  . ./lib/permissions.sh
  init
  override
  configure_permissions \
    || print_status unsuccessful_function error "configure_permissions"
  configure_partitions \
    || print_status unsuccessful_function error "configure_partitions"
  configure_grub \
    || print_status unsuccessful_function error "configure_grub"
  disable_kernel_modules \
    || print_status unsuccessful_function error "disable_kernel_modules"
  configure_sysctl \
    || print_status unsuccessful_function error "configure_sysctl"
  configure_mac \
    || print_status unsuccessful_function error "configure_mac"
  exit 0
fi

# source scripts from ./lib
. ./lib/initialization.sh
. ./lib/utility.sh
. ./lib/menu.sh
. ./lib/status.sh
. ./lib/firewall.sh
. ./lib/kernel.sh
. ./lib/logging.sh
. ./lib/packages.sh
. ./lib/permissions.sh
. ./lib/not-yet-implemented.sh

# Print the main menu
print_main_menu() {
  printf "%b%s%b\n" "${GREEN}${BOLD}" "Welcome to harden.sh" "${NC}"
  printf "%b%s%b\n" "${GREEN}" \
    "Options are organized into the sections Tools, Packages, Quick, and Heavy" \
    "${NC}"
  printf "%b%s%b\n" "$GREEN" "Enter the name of an option below:" "$NC"
  generate_menu_options main tools packages quick heavy
  printf "\n"
}

# Creates the interactable main menu, and also performs setup tasks
main() {
  do_before
  init
  do_after
  override

  if [[ "$SKIP_PKG_CHK" == "true" ]]; then
    print_status message info "Skipping potentially unwanted package checks"
    PACKAGES=()
  else
    check_installed_packages || print_status unsuccessful_function error \
      "check_installed_packages"
  fi
  if [[ "${#PACKAGES[@]}" -gt 0 ]]; then
    print_status message warn \
      "Potentially unwanted packages found, run remove/r to review them"
  fi

  while true; do
    print_main_menu
    while true; do
      read -erp "$(print_prompt)"
      case $REPLY in
        backup | b)
          backup_directories "$ARG_DIRECTORY" "$ARG_SUBDIRECTORY" \
            || print_status unsuccessful_function error \
              "backup_directories"
          ;;
        pscf | f)
          pscf || print_status unsuccessful_function error "pscf"
          ;;
        pscs | S)
          pscs || print_status unsuccessful_function error "pscs"
          ;;
        ssc | s)
          ssc || print_status unsuccessful_function error "ssc"
          ;;
        upgrade | up)
          upgrade_system "$PKG_MANAGER" \
            || print_status unsuccessful_function error \
              "upgrade_system"
          ;;
        remove | rm)
          ask_to_remove_packages \
            || print_status unsuccessful_function error \
              "ask_to_remove_packages"
          check_installed_packages \
            || print_status unsuccessful_function error \
              "check_installed_packages"
          ;;
        install | in)
          local option_one
          local option_two
          local remote_logging="journal_remote"
          while true; do
            read -erp "Install systemd-journal-remote? (y/n): " \
              option_one
            case $option_one in
              y)
                option_one="true" && break
                ;;
              n)
                remote_logging="rsyslog" && break
                ;;
              *)
                print_status unrecognized_option error "$option_one"
                ;;
            esac
          done

          if [[ "$remote_logging" == "rsyslog" ]]; then
            while true; do
              read -erp "Install rsyslog instead? (y/n): " \
                option_one
              case $option_one in
                y)
                  option_one="true" && break
                  ;;
                n)
                  option_one="false" && break
                  ;;
                *)
                  print_status unrecognized_option error "$option_one"
                  ;;
              esac
            done
          fi

          while true; do
            read -erp "Install extra security packages? (y/n): " \
              option_two
            case $option_two in
              y)
                option_two="true" && break
                ;;
              n)
                option_two="false" && break
                ;;
              *)
                print_status unrecognized_option error "$option_two"
                ;;
            esac
          done

          install_recommended_packages \
            "${remote_logging}=${option_one}" \
            "extra_security=$option_two" \
            || print_status unsuccessful_function error \
              "install_recommended_packages"
          option_one=""
          option_two=""
          ;;
        download | dl)
          download_software \
          || print_status unsuccessful_function error \
            "download_software"
          ;;
        mac)
          configure_mac \
            || print_status unsuccessful_function error \
              "configure_mac"
          ;;
        fwinit | fwi)
          init_firewall \
            || print_status unsuccessful_function error \
              "init_firewall"
          ;;
        fwconf | fwc)
          jclr
          configure_firewall \
            || print_status unsuccessful_function error \
              "configure_firewall"
          ;;
        logging | log)
          local option_one="false"
          local option_two="false"
          local journal_remote="false"
          local rsyslog="false"
          while true; do
            read -erp "Configure systemd-journal-remote? (y/n): " \
              option_one
            case $option_one in
              y)
                journal_remote="true" && break
                ;;
              n)
                break
                ;;
              *)
                print_status unrecognized_option error "$option_one"
                ;;
            esac
          done

          if [[ "$journal_remote" == "false" ]]; then
            while true; do
              read -erp "Configure rsyslog for remote logging instead? (y/n): " \
                option_two
              case $option_two in
                y)
                  rsyslog="true" && break
                  ;;
                n)
                  break
                  ;;
                *)
                  print_status unrecognized_option error "$option_two"
                  ;;
              esac
            done
          fi
          configure_logging journal_remote="$journal_remote" rsyslog="$rsyslog" \
            || print_status unsuccessful_function error \
              "configure_logging"
          ;;
        audit | aud)
          configure_auditd \
            || print_status unsuccessful_function error \
              "configure_auditd"
          ;;
        aide | aid)
          configure_aide \
            || print_status unsuccessful_function error \
              "configure_aide"
          ;;
        grub)
          configure_grub \
            || print_status unsuccessful_function error \
              "configure_grub"
          ;;
        perms)
          configure_permissions \
            || print_status unsuccessful_function error \
              "configure_permissions"
          ;;
        parts)
          configure_partitions \
            || print_status unsuccessful_function error \
              "configure_partitions"
          ;;
        mods)
          disable_kernel_modules \
            || print_status unsuccessful_function error \
              "disable_kernel_modules"
          ;;
        sys)
          local option_one
          while true; do
            read -erp "Disable IPv6? (y/n): " option_one
            case $option_one in
              y)
                option_one="true" && break
                ;;
              n)
                option_one="false" && break
                ;;
              *)
                print_status unrecognized_option error "$option_one"
                ;;
            esac
          done

          configure_sysctl "disable_ipv6=$option_one"
          option_one=""
          ;;
        init | i)
          jclr
          init
          override
          read -erp "Press enter to continue "
          ;;
        quit | q) 
          exit 0
          ;;
        bash | B)
          jclr
          print_status message info \
            "Placing you into a bash shell... Use ctrl + d/exit to exit"
          bash -l
          ;;
        *)
          print_status unrecognized_option error "$REPLY" rude
          REPLY=""
          continue
          ;;
      esac
      REPLY=""
      break
    done
  done
  return 0
}

if [[ "$SKIP_MAIN" != "true" ]]; then
  main
fi
