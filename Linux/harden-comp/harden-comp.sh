#!/bin/bash
# shellcheck source=/dev/null

# Want to get close to Google's styleguide?
# Run shfmt -i 2 -ci -bn

# Check ./lib/not-yet-implemented for TODOs

set -euo pipefail
set +H

SCRIPT_VERSION="v1.0.2"
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

# Set to "true" if you want to ignore the main menu,
# possibly to run functions directly
SKIP_MAIN="false"
# Set to "true" if you don't want to check for PUPs
SKIP_PKG_CHK="false"

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

# For testing purposes, will execute before init() within main()
do_before() {
  return 0
}

# For testing purposes, will execute after init() within main()
do_after() {
  return 0
}

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

# Check for OPTIONS passed
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      cat << EOF
Usage: sudo ./harden-comp.sh [OPTIONS]...
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
  sudo ./harden-comp.sh --backup /srv/backups

  Set backup directory as /srv/backups and backup subdirectory as /alt
  sudo ./harden-comp.sh -b /srv/backups -B /alt

  Set backup directory as /backups and backup subdirectory as /alt and set -x
  sudo ./harden-comp.sh --backup /backups -B /alt -x

  Set full backup directory as /usr/bin/alt and override firewall to nftables
  sudo ./harden-comp.sh --backup-subdir /alt -f nftables

  Set backup directory as /backups and backup subdirectory as /net and skip main
  sudo ./harden-comp.sh -b /backups --backup-subdir /net -s

  Override distribution to fedora, package manager to yum, and firewall to ufw
  sudo ./harden-comp.sh -d fedora -p yum -f ufw

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

harden-comp.sh ${SCRIPT_VERSION}
from Security Scripts
For more information, please visit the GitHub page.
<https://github.com/MichaelUrbano/Security-Scripts>.
Report bugs and issues on the Issues page.
Report vulnerabilities directly to git@michaelurbano.com
EOF
      exit 0
      ;;
    --version)
      cat << EOF
harden-comp.sh ${SCRIPT_VERSION} from Security Scripts
Copyright (C) 2025 Michael Urbano
Licensed under the BSD 3-Clause License
See: https://opensource.org/licenses/BSD-3-Clause

EOF
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
      ARG_DISTRO="$2"
      shift 2
      ;;
    -e | --no-errfail)
      set +e
      shift
      ;;
    -f | --firewall)
      ARG_FW="$2"
      shift 2
      ;;
    -i | --init)
      check_root
      . ./lib/error.sh
      . ./lib/initialization.sh
      init
      exit 0
      ;;
    -p | --pkg-manager)
      ARG_PM="$2"
      shift 2
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
      ARG_VER="$2"
      shift 2
      ;;
    -x | --xtrace)
      set -x
      shift
      ;;
    *)
      printf "Usage: sudo ./harden-comp.sh [OPTIONS]...\n"
      printf "Try './harden-comp.sh -h' for more information.\n"
      exit 1
  esac
done

check_root

if [[ "$ARG_BACKUP" == "enabled" ]]; then
  . ./lib/error.sh
  . ./lib/utility.sh
  backup_directories "$ARG_DIRECTORY" "$ARG_SUBDIRECTORY" \
  || print_status unsuccessful_function error \
    "backup_directories"
  exit 0
fi
if [[ "$ARG_QUICK" == "enabled" ]]; then
  . ./lib/initialization.sh
  . ./lib/utility.sh
  . ./lib/error.sh
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
. ./lib/error.sh
. ./lib/firewall.sh
. ./lib/kernel.sh
. ./lib/logging.sh
. ./lib/packages.sh
. ./lib/permissions.sh
. ./lib/not-yet-implemented.sh

# Print the options available
print_main_menu() {
  printf "%b%s%b\n" "${GREEN}${BOLD}" "Welcome to harden-comp.sh" "${NC}"
  printf "%b%s%b\n" "${GREEN}" \
    "Options are organized into the sections Tools, Packages, Quick, and Heavy" \
    "${NC}"
  printf "%b%s%b\n" "$GREEN" "Enter the name of an option below:" "$NC"

  printf "\n%b%-17s%b:\t%s\n" "${GREEN}${BOLD}" "Tools" "${GREEN}" \
    "Useful for operation of the script"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "B | backup" "${NC}" \
    "Will backup \"important directories\""
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "i | init" "${NC}" \
    "Show initial information gathered at beginning of the script"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "p | pms" "${NC}" \
    "Not Yet Implemented: Poor Man's SIEM"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "b | bash" "${NC}" \
    "Enter a bash login shell within the script"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "q | quit" \
    "${NC}" "Exit program"

  printf "\n%b%-17s%b:\t%s\n" "${GREEN}${BOLD}" "Packages" "${GREEN}" \
    "Automated upgrades, removals, and installations"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "up | upgrade" "${NC}" \
    "Upgrades the system"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "rm | remove" "${NC}" \
    "Asks to remove potentially unwanted packages"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "in | install" "${NC}" \
    "Asks to install potentially helpful packages"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "dl | download" "${NC}" \
    "Asks to download potentially helpful software"

  printf "\n%b%-17s%b:\t%s\n" "${GREEN}${BOLD}" "Quick" "${GREEN}" \
    "Run instantly + don't require package installs (usually)"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "grub" "${NC}" \
    "Configures bootloader parameters"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "perms" "${NC}" \
    "Reconfigures permissions for files and directories"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "parts" "${NC}" \
    "Sets secure mount options for partitions"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "mods" "${NC}" \
    "Disables unused kernel modules"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "sys" "${NC}" \
    "Reconfigures kernel parameters"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "mac" "${NC}" \
    "Sets up AppArmor/SELinux"

  printf "\n%b%-17s%b:\t%s\n" "${GREEN}${BOLD}" "Heavy" "${GREEN}" \
    "May require package installs"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "fwi | fwinit" "${NC}" \
    "Initializes the firewall on the system"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "fwc | fwconf" "${NC}" \
    "Helps you configure in/out firewall rules"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "log | logging" "${NC}" \
    "Initializes and configures journald or rsyslog"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "aud | audit" "${NC}" \
    "Initializes auditd configuration and rules"
  printf "%b%-17s%b:\t%s\n" "${YELLOW}${BOLD}" "aid | aide" "${NC}" \
    "Initializes AIDE (may take awhile)"

  printf "\n"
}

# Will present the main menu
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
      read -rp "harden-comp> "
      case $REPLY in
        backup | b)
          backup_directories "$ARG_DIRECTORY" "$ARG_SUBDIRECTORY" \
            || print_status unsuccessful_function error \
              "backup_directories"
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
            read -rp "Install systemd-journal-remote? (y/n): " \
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
              read -rp "Install rsyslog instead? (y/n): " \
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
            read -rp "Install extra security packages? (y/n): " \
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
            read -rp "Configure systemd-journal-remote? (y/n): " \
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
              read -rp "Configure rsyslog for remote logging instead? (y/n): " \
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
            read -rp "Disable IPv6? (y/n): " option_one
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
          read -rp "Press enter to continue "
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
