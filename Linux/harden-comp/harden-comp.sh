#!/bin/bash

# CIS DEBIAN 12 SECTIONS:
# 1: Initial Setup
# 2: Services
# 3: Network
# 4: Host Based Firewall
# 5: Access Control
# 6: Logging and Auditing
# 7: System Maintenance

# Ignored CIS Debian 12: 1.1.1.10, 1.2.1, 1.2.2 (partially), 1.6.1-3, 2.3, 2.4.1.8, 2.4.2
# Explanation: They are far too manual of processes to be included in the script in a meaningful way.

# Ignored CIS Debian 12: 1.7.2-10
# Explanation: You should not have a DE installed on a server, it presents a wider attack surface. GNOME + GDM should be removed

# Ignored CIS Debian 12: 3.1.2-3
# Explanation: Likely out of scope for competitions

# Ignored CIS Debian 12: 3.3.1-2, 3.3.5-6, 3.3.7 (partially), 3.3.8, 3.3.11
# Explanation: Could likely cause issues if VMs are in the cloud. That and I don't understand networking enough to change these with confidence

# Ignored CIS Debian 12: 5.1.2-22
# Explanation: SSH is typically nuked, so little focus will be put into configuring sshd

# Ignored CIS Debian 12: 5.2.2-7
# Explanation: Configuration of /etc/sudoers may vary in-between systems, so it won't be touched at the moment.

# Ignored CIS Debian 12: 5.3, 5.4.1
# Explanation: They are password hardening related, typically don't need to change for competitions(?)

# TODO: please implement 2.1.22 in some way (ss -tulpn)
# TODO: 7.1.13 could likely be implemented via linpeas.sh

# TODO: (5.4.2)

# TODO: (5.4.3.1, 5.4.3.2-3(?))

# TODO: (6.1.1, 6.1.4), (6.1.2-3 (maybe))

# TODO: auditd autoconfig (6.2), including adding .rules files to /etc/audit/rules.d/ (specified in 6.2.3)

# TODO: Supplementary security tools autoconfig (fail2ban, ossec, clamav, chkrootkit, lynis)

# TODO: Get helper functions for implementing colors into printf statements
# TODO: Create error functions
# TODO: Use printf instead of echo where appropriate
# TODO: Implement a logging system

# Want to get close to Google's styleguide?
# Run shfmt -i 2 -ci -bn

set -euo pipefail
set +H

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

# Check root
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

. ./lib/initialization.sh
. ./lib/backup.sh
. ./lib/error.sh
. ./lib/firewall.sh
. ./lib/kernel.sh
. ./lib/logging.sh
. ./lib/packages.sh
. ./lib/permissions.sh

# Set to "true" if you want to ignore the main menu,
# possibly to run functions directly
SKIP_MAIN="false"

# For testing purposes, will execute before init() within main()
do_before() {
  return 0
}

# For testing purposes, will execute after init() within main()
do_after() {
  return 0
}

configure_fail2ban() {
  return 1
}

configure_clamav() {
  return 1
}

configure_sudo() {
  return 1
}

configure_sshd() {
  return 1
}

configure_authentication() {
  return 1
}

# Will present the main menu
main() {
  clear
  do_before
  init
  do_after

  check_installed_packages || print_status unsuccessful_function error \
    "check_installed_packages"
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
          backup_directories \
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
          { [[ -f $HOME/.env ]] && . "$HOME/.env" &>/dev/null; } || :
          ;;
        exit | quit | q | ex) exit 0 ;;
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
