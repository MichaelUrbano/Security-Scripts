#!/bin/bash

# Want to get close to Google's styleguide?
# Run shfmt -i 2 -ci -bn

# Check ./lib/not-yet-implemented for TODOs

set -euo pipefail
set +H

SCRIPT_VERSION="0.0.0-not-yet-versioned"
ARG_DIRECTORY=""
ARG_SUBDIRECTORY=""
ARG_DISTRO=""
ARG_FW=""
ARG_PM=""
ARG_VER=""

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

# Check for OPTIONS passed
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      cat << EOF
Usage: sudo ./harden-comp.sh [OPTIONS]...
Hardening and utility script for competitions

OPTIONS:
  -b, --backup DIRECTORY    send backups to/check for backups in DEST/b4
                              (default /usr/bin)
  -B, --backup-subdirectory DIRECTORY
                            change backup subdirectory
                              (default /b4)
  -d, --distro DIST         override distribution
  -e, --no-errfail          will set +e on the script, preventing the script
                              from exiting on any non-zero status (DANGEROUS)
  -f, --firewall FW         override firewall
  -i, --init                show information from init() function, then exit
  -p, --pkg-manager PM      override package manager
  -P, --skip-pkg-chk        skips check_installed_packages() inside of main()
  -q, --quick               run all options under Quick, then exit
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

The DIST argument can be ubuntu, debian, opensuse, centos, rocky, almalinux,
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

From Security-Scripts, by Michael Urbano.
For more information, please visit GitHub.
<https://github.com/MichaelUrbano/Security-Scripts>.
Report bugs, vulnerabilties, or other issues to git@michaelurbano.com
EOF
      exit 0
      ;;
    --version)
      printf "%s\n" "$SCRIPT_VERSION"
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
    -q | --quick)
      :
      exit 0
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

# source scripts from ./lib
. ./lib/initialization.sh
. ./lib/backup.sh
. ./lib/error.sh
. ./lib/firewall.sh
. ./lib/kernel.sh
. ./lib/logging.sh
. ./lib/packages.sh
. ./lib/permissions.sh
. ./lib/not-yet-implemented.sh

override() {
  if [[ -n "$ARG_DISTRO" ]]; then
    DISTRO="$ARG_DISTRO"
  fi
  if [[ -n "$ARG_VER" ]]; then
    VER="$ARG_VER"
  fi
  if [[ -n "$ARG_PM" ]]; then
    PKG_MANAGER="$ARG_PM"
  fi
  if [[ -n "$ARG_FW" ]]; then
    FIREWALLS=("$ARG_FW")
  fi
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
    printf "${GREEN}%s${NC}\n" \
      "Welcome to Michael's Linux Hardening Script (Competition Edition)"
    printf "${GREEN}%s${NC}\n" \
      "Options are organized into the sections Tools, Packages, Quick, and Heavy"
    printf "${GREEN}%s${NC}\n" \
      "Enter the name of an option below:"

    printf "\n${GREEN}${BOLD}%-10s${NC}${GREEN} :\t %s\n" \
      "Tools" "Useful for operation of the script"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "backup" "Will back up \"important directories\""
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "init" "Show inital information gathered at beginning of the script"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "exit" "Exit program"

    printf "\n${GREEN}${BOLD}%-10s${NC}${GREEN} :\t %s\n" \
      "Packages" "Automated upgrades, removals, and installations"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "upgrade" "Upgrades the system"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "remove" "Asks to remove potentially unwanted packages"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "install" "Asks to install potentially helpful packages"

    printf "\n${GREEN}${BOLD}%-10s${NC}${GREEN} :\t %s\n" \
      "Quick" "Run instantly + don't require package installs (usually)"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "grub" "Configures bootloader parameters"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "perms" \
      "Reconfigures permissions for files and directories"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "parts" "Sets secure mount options for partitions"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "modules" "Disables unused kernel modules"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "sysctl" "Reconfigures kernel parameters"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "mac" "Sets up AppArmor/SELinux"

    printf "\n${GREEN}${BOLD}%-10s${NC}${GREEN} :\t %s\n" \
      "Heavy" "May require package installs"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "fwinit" "Initializes the firewall on the system"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "fwconf" "Helps you configure in/out firewall rules"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "logs" "Initializes and configures journald or rsyslog"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "audit" "Initializes auditd configuration and rules"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" \
      "aide" "Initializes AIDE (may take awhile)"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t ${RED}%s${NC}\n" \
      "clam" "Not Yet Implemented: Initializes and configures ClamAV"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t ${RED}%s${NC}\n" \
      "fail" "Not Yet Implemented: Helps you configure fail2ban"
    printf "\n"

    while true; do
      read -rp "Enter an option: "
      case $REPLY in
        backup | b)
          backup_directories "$ARG_DIRECTORY" "$ARG_SUBDIRECTORY" \
            || print_status unsuccessful_function error \
              "backup_directories"
          ;;
        upgrade | u)
          upgrade_system "$PKG_MANAGER" \
            || print_status unsuccessful_function error \
              "upgrade_system"
          ;;
        remove | r)
          print_status message warn \
            "Potentially unwated packages found:"
          for pkg in "${PACKAGES[@]}"; do
            printf "%b%s%b " "$RED" "$pkg" "$NC"
          done
          ask_to_remove_packages \
            || print_status unsuccessful_function error \
              "ask_to_remove_packages"
          check_installed_packages \
            || print_status unsuccessful_function error \
              "check_installed_packages"
          ;;
        install | i)
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
                printf "${RED}%s${NC}\n" \
                  "Unrecognized option, try again"
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
                  printf "${RED}%s${NC}\n" \
                    "Unrecognized option, try again"
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
                printf "${RED}%s${NC}\n" \
                  "Unrecognized option, try again"
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
        mac)
          configure_mac \
            || print_status unsuccessful_function error \
              "configure_mac"
          ;;
        fwinit)
          init_firewall \
            || print_status unsuccessful_function error \
              "init_firewall"
          ;;
        fwconf)
          clear
          configure_firewall \
            || print_status unsuccessful_function error \
              "configure_firewall"
          ;;
        logs)
          local option_one="false"
          local option_two="false"
          while true; do
            read -rp "Configure systemd-journal-remote? (y/n): " \
              option_one
            case $option_one in
              y)
                option_one="true" && break
                ;;
              n)
                break
                ;;
              *)
                printf "${RED}%s${NC}\n" \
                  "Unrecognized option, try again"
                ;;
            esac
          done

          if [[ "$option_one" == "false" ]]; then
            while true; do
              read -rp "Configure rsyslog for remote logging instead? (y/n): " \
                option_two
              case $option_two in
                y)
                  option_two="true" && break
                  ;;
                n)
                  break
                  ;;
                *)
                  printf "${RED}%s${NC}\n" \
                    "Unrecognized option, try again"
                  ;;
              esac
            done
          fi
          configure_logging journal_remote="$option_one" rsyslog="$option_two" \
            || print_status unsuccessful_function error \
              "configure_logging"
          ;;
        audit)
          configure_auditd \
            || print_status unsuccessful_function error \
              "configure_auditd"
          ;;
        aide)
          configure_aide \
            || print_status unsuccessful_function error \
              "configure_aide"
          ;;
        fail)
          configure_fail2ban \
            || print_status unsuccessful_function error \
              "configure_fail2ban"
          ;;
        clam)
          configure_clamav \
            || print_status unsuccessful_function error \
              "configure_clamav"
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
        modules)
          disable_kernel_modules \
            || print_status unsuccessful_function error \
              "disable_kernel_modules"
          ;;
        sysctl)
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
                printf "${RED}%s${NC}\n" \
                  "Unrecognized option, try again"
                ;;
            esac
          done

          configure_sysctl "disable_ipv6=$option_one"
          option_one=""
          ;;
        init)
          clear
          init
          read -rp "Press enter to continue "
          ;;
        exit | quit | q | ex) 
          exit 0
          ;;
        bash)
          clear
          print_status message info \
            "Placing you into a bash shell... Use ctrl + d/exit to exit"
          bash -l
          ;;
        *)
          printf "${RED}%s${NC}\n" "Unrecognized option, try again"
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
