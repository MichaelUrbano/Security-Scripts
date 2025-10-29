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

# Set ANSI Escape Code variables for different colors in the terminal, as well as recommended, but not strict, usage of colors.
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
  printf "%bThis script must be run as%b %broot%b%b, or with%b %bsudo%b%b.%b\n" \
    "$YELLOW" "$NC" \
    "${RED}${BOLD}" "$NC" \
    "$YELLOW" "$NC" \
    "${RED}${BOLD}" "$NC" \
    "$YELLOW" "$NC"
  exit 1
fi

# Set to "true" if you want to ignore the main menu,
# possibly to run functions directly
SKIP_MAIN="false"

# Silently import .env before init even can, in case user set SKIP_MAIN="true"
. "$HOME/.env" &>/dev/null || true

# For testing purposes, will execute before init() within main()
do_before() {
  return 0
}

# For testing purposes, will execute after init() within main()
do_after() {
  return 0
}

# Helper function to print status messages
# print_status "message|not_found" "error|warn|info|success" "..."
print_status() {
  local name="$1"
  shift
  "prst_${name}" "$@" || printf "%b%s%b\n" "$UC" "Unknown Error" "$UC"
}

# Generic status message
# print_status message status "text"
prst_message() {
  local input_status="$1"
  local input_text="$2"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$input_text" "$NC"
}

# Generic status message for text, with an object appended at the end
# print_status message_object status object "text" "object"
prst_message_object() {
  local input_status="$1"
  local input_object="$2"
  local input_text="$3"
  local object_text="$4"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  case "$input_object" in
    file) local object="$object_text" object_color="$CYAN" ;;
    directory) local object="$object_text" object_color="$MAGENTA" ;;
    command | function) local object="$object_text" object_color="${YELLOW}${BOLD}" ;;
    option) local object="$object_text" object_color="$YELLOW" ;;
    *) local object="$object_text" object_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$input_text" "$NC" \
    "$object_color" "$object" "$NC"
}

# prst_message with a few quirks
# Intended as a temporary, hacky workaround solution while other coding
# tasks are prioritized
# You give it the first portion of the string that you would normally print
# The second argument should be the rest of the string that you
# would like to print, though you cannot, since it is with a different color
# The two strings will then be combined for logging purposes
# (once logging is implemented)
# It has no newline character, so from there you would use
# printf to change the color of the following text
# Useful for when you may need to use custom colors after a status message,
# for things like file or directory names
# Example w/ printf afterwards:
# print_status message_alt warn \
# "Distribution could not be determined, placing in both" \
# "/etc/nftables.conf and /etc/sysconfig/nftables.conf"
# printf "%b%s%b and %b%s%b\n" \
# "$CYAN" "/etc/nftables.conf" "$NC" \
# "$CYAN" "/etc/sysconfig/nftables.conf" "$NC"
# print_status message_alt "error|warn|info|success" \
# "partial printed text" "logged text"
prst_message_alt() {
  case "$1" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$2" "$NC"
}

# Not found status message
# print_status not_found "error|warn" "file|directory|*" "path"
prst_not_found() {
  case "$2" in
    file)
      case "$1" in
        error)
          printf "%b[ERROR]%b %bfile not found:%b %b%s%b\n" "$EC" "$NC" "$RED" "$NC" "${CYAN}${BOLD}" "$2" "$NC"
          ;;
        warn)
          printf "%b[ERROR]%b %bfile not found:%b %b%s%b\n" "$WC" "$NC" "$YELLOW" "$NC" "${CYAN}${BOLD}" "$2" "$NC"
          ;;
      esac
      ;;

    directory)
      case "$1" in
        error)
          printf "%b[ERROR]%b %bdirectory not found:%b %b%s%b\n" "$EC" "$NC" "$RED" "$NC" "${MAGENTA}${BOLD}" "$2" "$NC"
          ;;
        warn)
          printf "%b[WARN]%b %bdirectory not found:%b %b%s%b\n" "$WC" "$NC" "$YELLOW" "$NC" "${MAGENTA}${BOLD}" "$2" "$NC"
          ;;
      esac
      ;;

    *)
      printf "not found: %s\n" "$2"
      ;;
  esac
}

# Already Exists status message
# print_status already_exists "error|warn" "file|directory|*" "path" "kind|rude"
prst_already_exists() {
  case "$2" in
    file)
      case "$1" in
        error)
          printf "%b[ERROR]%b %bfile already exists:%b %b%s%b%b" "$EC" "$NC" "$RED" "$NC" "${CYAN}${BOLD}" "$3" "$NC" "$RED"
          ;;
        warn)
          printf "%b[ERROR]%b %bfile already exists:%b %b%s%b%b" "$WC" "$NC" "$YELLOW" "$NC" "${CYAN}${BOLD}" "$3" "$NC" "$YELLOW"
          ;;
      esac
      ;;
    directory)
      case "$1" in
        error)
          printf "%b[ERROR]%b %bdirectory already exists:%b %b%s%b%b" "$EC" "$NC" "$RED" "$NC" "${MAGENTA}${BOLD}" "$3" "$NC" "$RED"
          ;;
        warn)
          printf "%b[WARN]%b %bdirectory already exists:%b %b%s%b%b" "$WC" "$NC" "$YELLOW" "$NC" "${MAGENTA}${BOLD}" "$3" "$NC" "$YELLOW"
          ;;
      esac
      ;;
    *)
      printf "not found: %s\n" "$3"
      ;;
  esac
  case "$4" in
    kind) printf ", Please remove it if you would like to try again\n" ;;
    rude | *) printf "\n" ;;
  esac
}

# using "package-manager" to install "package"
# print_status using_to status "install|remove" "package-manager" "package"
prst_using_to() {
  case "$1" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  case "$2" in
    install) local action="install" ;;
    remove) local action="remove" ;;
    *) local action="$2" ;;
  esac
  printf "%b[%s]%b %bUsing%b %b%s%b %bto %s%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$NC" \
    "$YELLOW" "$3" "$NC" \
    "$text_color" "$action" "$NC" \
    "$YELLOW" "$4" "$NC"
}

# Not installed: package status message
# print_status not_installed status "package"
prst_not_installed() {
  case "$1" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b: %bnot installed%b\n" \
    "$status_color" "$status" "$NC" \
    "$YELLOW" "$2" "$NC" \
    "$text_color" "$NC"
}
# Invalid input status message
# print_status invalid_input "error|info" "input"
prst_invalid_input() {
  case "$1" in
    error)
      printf "%b[ERROR]%b %bInvalid input:%b %b%s%b\n" "$EC" "$NC" "$RED" "$NC" "$RED" "$2" "$NC"
      ;;
    info)
      printf "%b[INFO]%b %bInvalid input:%b %b%s%b\n" "$IC" "$NC" "$BLUE" "$NC" "$BLUE" "$2" "$NC"
      ;;
    *)
      printf "Invalid input: %s\n" "$2"
      ;;
  esac
}

# Unrecognized option status message
# print_status unrecognized_option "error|info" "input"
prst_unrecognized_option() {
  case "$1" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %bUnrecognized option:%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$NC" \
    "$text_color" "$2" "$NC"
}

# object found in file alert message
# print_status found_in alert "input" "path"
prst_found_in() {
  case "$1" in
    *) local status="ALERT" status_color="$EC" text_color="$EC" ;;
  esac
  printf "%b[%s]%b %b%s%b %bfound in%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "${YELLOW}${BOLD}" "$2" "$NC" \
    "$text_color" "$NC" \
    "$CYAN" "$3" "$NC"
}

# Duplicate object found in file alert message
# print_status duplicate_found_in alert "input" "path"
prst_duplicate_found_in() {
  case "$1" in
    *) local status="ALERT" status_color="$EC" text_color="$EC" ;;
  esac
  printf "%b[%s]%b %bDuplicate%b %b%s%b %bfound in%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$NC" \
    "${YELLOW}${BOLD}" "$2" "$NC" \
    "$text_color" "$NC" \
    "$CYAN" "$3" "$NC"
}

# print_status unsuccessful_function "error|warn" "function"
prst_unsuccessful_function() {
  case "$1" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b %bdid not complete successfully%b\n" \
    "$status_color" "$status" "$NC" \
    "${YELLOW}${BOLD}" "$2" "$NC" \
    "$text_color" "$NC"
}

install_package() {
  local package_manager="$1"
  if [[ -z "$package_manager" ]]; then
    print_status message error "No package manager specified"
    return 1
  fi

  local package_name="$2"
  if [[ -z "$package_name" ]]; then
    print_status message error "No package name specified"
    return 1
  fi

  if [[ "$package_manager" == "unsupported" ]]; then
    print_status message error "Unsupported package manager"
    return 1
  fi

  case "$package_manager" in
    apt)
      print_status using_to info install "apt" "$package_name"
      apt install -y "$package_name"
      ;;
    dnf)
      print_status using_to info install "dnf" "$package_name"
      dnf install -y "$package_name"
      ;;
    yum)
      print_status using_to info install "yum" "$package_name"
      yum install -y "$package_name"
      ;;
    zypper)
      print_status using_to info install "zypper" "$package_name"
      zypper install -y "$package_name"
      ;;
    pacman)
      print_status using_to info install "pacman" "$package_name"
      pacman -Syu --noconfirm "$package_name"
      ;;
    *)
      print_status message error "Unsupported package manager"
      return 1
      ;;
  esac
}

remove_package() {
  local package_manager="$1"
  if [[ -z "$package_manager" ]]; then
    print_status message error "No package manager specified"
    return 1
  fi

  local package_name="$2"
  if [[ -z "$package_name" ]]; then
    print_status message error "No package name specified"
    return 1
  fi

  if [[ "$package_manager" == "unsupported" ]]; then
    print_status message error "Unsupported package manager"
    return 1
  fi

  case "$package_manager" in
    apt)
      print_status using_to info remove "apt" "$package_name"
      apt remove "$package_name"
      ;;
    dnf)
      print_status using_to info remove "dnf" "$package_name"
      dnf remove "$package_name"
      ;;
    yum)
      print_status using_to info remove "yum" "$package_name"
      yum remove "$package_name"
      ;;
    zypper)
      print_status using_to info remove "zypper" "$package_name"
      zypper remove "$package_name"
      ;;
    pacman)
      print_status using_to info remove "pacman" "$package_name"
      pacman -R "$package_name"
      ;;
    *)
      print_status message error "Unsupported package manager"
      return 1
      ;;
  esac
}

# Checks system information and sets up global variables needed for functions
init() {
  print_status message info "Checking system information..."
  # Determine distro being used
  if [ -f /etc/os-release ]; then
    # freedesktop.org
    . /etc/os-release
    case "$ID" in
      ubuntu | debian | opensuse.* | centos | rocky | almalinux | fedora | rhel | ol)
        DISTRO=$ID
        VER=$VERSION_ID
        ;;
      *)
        DISTRO=${ID_LIKE%% *}
        VER="?"
        ;;
    esac
  elif type lsb_release &>/dev/null; then
    # linuxbase.org
    DISTRO=$(lsb_release -si)
    VER=$(lsb_release -sr)
  elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    DISTRO=$DISTRIB_ID
    VER=$DISTRIB_RELEASE
  elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    DISTRO=Debian
    VER=$(cat /etc/debian_version)
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    DISTRO=$(uname -s)
    VER=$(uname -r)
  fi
  DISTRO=$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')
  printf "%bDistribution ID:%b %s %s\n" "${GREEN}" "${NC}" "$DISTRO" "$VER"

  # Choose correct package manager for distro
  case "$DISTRO" in
    ubuntu | debian)
      if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
      else
        PKG_MANAGER="dpkg"
      fi
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      if command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
      elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
      else
        PKG_MANAGER="rpm"
      fi
      ;;
    opensuse*)
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
  declare -gA FW_BACKUPS=()

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
    ubuntu | debian | opensuse*)
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
  if [[ "$DISTRO" =~ ^(debian|ubuntu|opensuse.*)$ ]]; then
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

upgrade_system() {
  local package_manager="$1"
  if [[ -z "$package_manager" ]]; then
    echo "Error: No package manager provided to upgrade_system."
    return 1
  fi

  if [[ "$package_manager" == "unsupported" ]]; then
    echo "Error: Unsupported operating system."
    return 1
  fi

  case "$package_manager" in
    apt)
      echo "Using apt to upgrade system..."
      apt update && apt upgrade -y
      ;;
    dnf)
      echo "Using dnf to upgrade system..."
      dnf upgrade -y
      ;;
    yum)
      echo "Using yum to upgrade system..."
      yum upgrade -y
      ;;
    zypper)
      echo "Using zypper to upgrade system..."
      zypper up
      ;;
    pacman)
      echo "Using pacman to upgrade system..."
      pacman -Syu --noconfirm
      ;;
    *)
      echo "Error: Unsupported package manager."
      return 1
      ;;
  esac
}

# CIS Debian 2.1 & 2.2
check_installed_packages() {
  PACKAGES=()
  local pkg=""
  case $DISTRO in
    ubuntu | debian)
      local -ar candidate_pkgs=(
        autofs avahi-daemon isc-dhcp-server bind9 dnsmasq vsftpd slapd
        dovecot-imapd nfs-kernel-server ypserv cups rpcbind rsync samba
        snmpd tftpd-hpa squid apache2 nginx xinetd xserver-common nis
        rsh-client talk telnet inetutils-telnet ldap-utils ftp tnftp
        prelink apport gnome gdm3 bluez netcat-openbsd netcat-traditional
        ncat wireshark tshark tcpdump gcc make rsh-server telnetd nmap
        proftpd pure-ftpd inetutils-inetd openbsd-inetd rinetd rlinetd
        unbound lighttpd vnc-server tightvncserver
        tigervnc-standalone-server linuxvnc x11vnc cockpit
      )
      for pkg in "${candidate_pkgs[@]}"; do
        { dpkg-query -s "$pkg" &>/dev/null && PACKAGES+=("$pkg"); } \
          || true
      done
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      local -ar candidate_pkgs=(
        mcstrans setroubleshoot autofs avahi dhcp-server bind dnsmasq
        samba vsftpd dovecot cyrus-imapd nfs-utils ypserv cups
        rpcbind rsync-daemon net-snmp telnet-server tftp-server squid
        httpd nginx xinetd xorg-x11-server-common ftp openldap-clients
        ypbind telnet tftp @graphical-server-environment
        @workstation-product-environment bluez netcat nmap-ncat wireshark
        wireshark-cli tcpdump gcc make rsh rsh-server nmap proftpd
        pure-ftpd unbound lighttpd tigervnc-server
        tigervnc-server-minimal cockpit
      )
      for pkg in "${candidate_pkgs[@]}"; do
        { rpm -q "$pkg" &>/dev/null && PACKAGES+=("$pkg"); } || true
      done
      ;;
    *)
      print_status message error "Unrecognized package manager"
      return 1
      ;;
  esac
}

# CIS Ubuntu 2.1 & 2.2
# Requires user interaction
ask_to_remove_packages() {
  if [ ${#PACKAGES[@]} -eq 0 ]; then
    echo -e "${RED}There are no packages to remove. (did you run check_installed_packages?)${NC}"
    return 0
  fi
  echo -e "${BLUE}You will be asked if you want to remove each package${NC}"
  echo -e "${BLUE}look carefully at each, and determine if they are necessary or not.${NC}"
  local pkg
  for pkg in "${PACKAGES[@]}"; do
    remove_package "$PKG_MANAGER" "$pkg"
  done
}

install_recommended_packages() {
  local journal_remote="false"
  local rsyslog="false"
  local extra_security="false"
  local arg=""

  for arg in "$@"; do
    case "$arg" in
      journal_remote=true) journal_remote="true" ;;
      journal_remote=false) journal_remote="false" ;;
      rsyslog=true) rsyslog="true" ;;
      rsyslog=false) rsyslog="false" ;;
      extra_security=true) extra_security="true" ;;
      extra_security=false) extra_security="false" ;;
      *)
        print_status message_object error option "Unrecognized option:" "$arg"
        return 1
        ;;
    esac
  done

  case "$DISTRO" in
    ubuntu | debian)
      local -a packages=(
        "sudo" "apparmor" "apparmor-utils" "auditd" "audispd-plugins" "aide"
        "apparmor-profiles" "apparmor-profiles-extra"
      )
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      local -a packages=(
        "sudo" "libselinux" "audit" "aide" "selinux-policy"
        "selinux-policy-targeted"
      )
      ;;
    *)
      print_status message error "Unrecognized package manager"
      return 1
      ;;
  esac

  local pkg
  if [ "$journal_remote" = "true" ]; then
    packages+=("systemd-journal-remote")
  elif [ "$rsyslog" = "true" ]; then
    packages+=("rsyslog")
  fi
  if [ "$extra_security" = "true" ]; then
    packages+=("lynis" "clamav" "chkrootkit" "fail2ban")
  fi

  for pkg in "${packages[@]}"; do
    install_package "$PKG_MANAGER" "$pkg"
  done
}

download_software() {
  return 1
}

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

configure_mac() {
  case "$DISTRO" in
    ubuntu | debian | opensuse*)
      if ! command -v aa-enforce; then
        print_status message_object error command \
          "Could not run" "aa-enforce"
        return 1
      fi
      aa-enforce /etc/apparmor.d/* &>/dev/null || true
      aa-complain /usr/share/apparmor/extra-profiles/* || true
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      if ! grep -qE '^[[:blank:]]*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config; then
        sed -iE 's/^[[:blank:]]*SELINUXTYPE=.*\b/SELINUXTYPE=targeted/'
      fi
      if ! grep -qEi '^[[:blank:]]*SELINUX=(enforcing|permissive)' /etc/selinux/config; then
        sed -iE 's/^[[:blank:]]*SELINUX=.*\b/SELINUX=enforcing/'
        setenforce 1
      fi
      if ps -eZ | grep unconfined_service_t; then
        print_status message warn \
          "Please be aware there are unconfined processes on the system"
        ps -eZ | grep unconfined_service_t
      fi
      ;;

  esac
  return 1
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

# CIS Ubuntu: 4
# This is a function which will do some initialization for firewalls
# This function is not yet safe, 
# since it doesn't really do any actions atomically,
# or create backups of configurations
init_firewall() {
  # CIS Debian 12: 4.1
  if [ ${#FIREWALLS[@]} -eq 0 ]; then
    print_status message error "Please install a firewall onto the system, then try again."
    return 1
  fi

  # Checks should be put in place to see if a table/chain/rule already exists
  if [[ " ${FIREWALLS[*]} " =~ " firewalld " && $DISTRO =~ ^(centos|rocky|almalinux|fedora|rhel|ol)$ ]]; then
    {
      print_status message info "Backing up configuration (if it exists)..."
      backup_firewall firewalld init
      systemctl disable --now nftables &>/dev/null || true
      systemctl disable --now netfilter-persistent &>/dev/null || true
      systemctl disable --now ufw &>/dev/null || true
      firewall-cmd --permanent --set-default-zone=public
      firewall-cmd --permanent --zone=trusted --add-interface=lo
      firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
      firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
      firewall-cmd --permanent --add-rich-rule='rule family=ipv6 source address="::1" destination not address="::1" drop'
      firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family=ipv6 source address="::1" destination not address="::1" drop'
      systemctl enable --now firewalld
      firewall-cmd --reload
    } || {
      print_status message error "Something went wrong, exiting..."
      return 1
    }

  elif [[ " ${FIREWALLS[*]} " =~ " ufw " && $DISTRO =~ ^(ubuntu|debian)$ ]]; then
    {
      print_status message info "Backing up configuration (if it exists)..."
      backup_firewall ufw init
      systemctl disable --now nftables &>/dev/null || true
      systemctl disable --now netfilter-persistent &>/dev/null || true
      systemctl disable --now firewalld &>/dev/null || true
      ufw allow in on lo
      ufw allow out on lo
      ufw deny in from 127.0.0.0/8
      ufw deny in from ::1
      systemctl enable --now ufw
      ufw --force enable
    } || {
      print_status message error "Something went wrong, exiting..."
      return 1
    }

  elif [[ " ${FIREWALLS[*]} " =~ " nftables " ]]; then
    {
      print_status message info "Backing up configuration (if it exists)..."
      backup_firewall nftables init
      systemctl disable --now netfilter-persistent &>/dev/null || true
      systemctl disable --now firewalld &>/dev/null || true
      systemctl disable --now ufw &>/dev/null || true
      nft list table inet filter &>/dev/null || nft create table inet filter
      nft list chain inet filter INPUT &>/dev/null || nft create chain inet filter INPUT '{ type filter hook input priority filter ; }'
      nft list chain inet filter FORWARD &>/dev/null || nft create chain inet filter FORWARD '{ type filter hook forward priority filter ; policy drop ; }'
      nft list chain inet filter OUTPUT &>/dev/null || nft create chain inet filter OUTPUT '{ type filter hook output priority filter ; }'
      nft add rule inet filter INPUT iif lo accept
      nft add rule inet filter INPUT ip saddr 127.0.0.0/8 counter drop
      nft add rule inet filter INPUT ip protocol tcp ct state established accept
      nft add rule inet filter INPUT ip protocol udp ct state established accept
      nft add rule inet filter OUTPUT ip protocol tcp ct state new,related,established accept
      nft add rule inet filter OUTPUT ip protocol udp ct state new,related,established accept
      if [[ "$DISTRO" =~ ^(centos|rocky|almalinux|fedora|rhel|ol|opensuse.*)$ ]]; then
        nft list ruleset >/etc/sysconfig/nftables.conf
      elif [[ "$DISTRO" =~ ^(ubuntu|debian|arch)$ ]]; then
        nft list ruleset >/etc/nftables.conf
      else
        print_status message_alt warn "Distribution could not be determined, placing in both" "/etc/nftables.conf and /etc/sysconfig/nftables.conf"
        printf "%b%s%b and %b%s%b\n" "$CYAN" "/etc/nftables.conf" "$NC" "$CYAN" "/etc/sysconfig/nftables.conf" "$NC"
        nft list ruleset | tee /etc/nftables.conf /etc/sysconfig/nftables.conf >/dev/null
      fi
      systemctl enable --now nftables
    } || {
      print_status message error "Something went wrong, exiting..."
      return 1
    }

  elif [[ " ${FIREWALLS[*]} " =~ " iptables " ]]; then
    {
      print_status message info "Backing up configuration (if it exists)..."
      backup_firewall iptables init
      systemctl disable --now nftables &>/dev/null || true
      systemctl disable --now firewalld &>/dev/null || true
      systemctl disable --now ufw &>/dev/null || true
      iptables -F &>/dev/null || true
      iptables -P FORWARD DROP
      iptables -A INPUT -i lo -j ACCEPT
      iptables -A OUTPUT -o lo -j ACCEPT
      iptables -A INPUT -s 127.0.0.0/8 -j DROP
      iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
      iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
      iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
      iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
      iptables-save >/etc/iptables/rules.v4
      ip6tables -F &>/dev/null || true
      ip6tables -P FORWARD DROP
      ip6tables -A INPUT -i lo -j ACCEPT
      ip6tables -A OUTPUT -o lo -j ACCEPT
      ip6tables -A INPUT -s ::1 -j DROP
      ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
      ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
      ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
      ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
      ip6tables-save >/etc/iptables/rules.v6
      systemctl enable --now netfilter-persistent
    } || {
      print_status message error "Something went wrong, exiting..."
      return 1
    }
  else
    print_status message error "Unrecognized firewall"
    return 1
  fi
}

# User interactive function
configure_firewall() {
  if [ ${#FIREWALLS[@]} -eq 0 ]; then
    echo "Please install a firewall onto the system, then try again."
    return 1
  fi

  fw_help() {
    clear
    echo -e "Command options are as follows:"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "h|help" "Will show you this prompt again"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "q|quit" "Will quit to main menu, without saving any changes"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "a|append" "Allows you to append allow rules"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "s|show" "Will ask if you would like to finalize your configuration"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "l|list" "Will list available service names"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "d|delete" "Will let you delete a rule"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "r|reset" "Will show your currently configured rules"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "f|finalize" "Will reset your rules"
    echo -e "Long or short names for commands may be used."
    echo -e "You can set the allow rules you would like on the system with the ${YELLOW}a${NC} command"
    echo -e "No changes will be made to the actual firewall configuration until you enter the ${YELLOW}f${NC} command"
    echo -e "Please ensure you ran ${YELLOW}fwconf${NC} before this, otherwise you may encounter firewall issues"
    echo -e "${YELLOW}You may either enter the port number followed by the protocol (tcp | udp) in order to add an allow rule${NC}"
    echo -e "Example:"
    echo -e "Enter port/protocol or service name: 22 tcp"
    echo -e "${YELLOW}Alternatively, you may enter one of the generic names for a protocol below${NC}"
    echo -e "Example:"
    echo -e "Enter port/protocol or service name: ssh"
  }

  fw_add_rules() {
    local service="" protocol="" valid_port="false" valid_name="false" append="" rule=""
    while true; do
      read -rp "Enter port/protocol or service name (q to exit): " service protocol
      # For verifying that given input is valid
      if [[ "$service" =~ ^[0-9]+$ ]]; then           # Is input only numbers?
        if ((service >= 1 && service <= 65535)); then # Is input a valid port number?
          if [[ "$protocol" =~ ^(tcp|udp)$ ]]; then   # Did they specify a valid protocol?
            valid_port="true"
            append="${service}/${protocol}"
          fi
        fi
      elif [[ "$service" =~ ^[a-z\-]+[a-z0-9]$ ]]; then # Is input letters/dashes, ending with a letter or 1 digit? (ex: "pop3" and "ssh" will match, but not "prot42")
        local service_name=""
        local attempted_service=""
        for service_name in "${service_ports[@]}"; do # Does the input service exist in the array?
          attempted_service=$(echo "$service_name" | cut -d ":" -f 1)
          if [[ "$attempted_service" = "$service" ]]; then
            valid_name="true"
            append=$(echo "$service_name" | cut -d ":" -f 2)
          fi
        done
      elif [[ "$service" = "q" ]]; then # did they type q talso_doo exit?
        return 0
      else
        echo -e "${RED}Invalid input${NC}"
        service=""
        protocol=""
        valid_port="false"
        valid_name="false"
        append=""
        continue
      fi

      for rule in "${rulelist[@]}"; do
        if [[ "$rule" = "$append" ]]; then
          echo -e "${RED}Rule already exists.${NC}"
          service=""
          protocol=""
          valid_port="false"
          valid_name="false"
          append=""
          continue 2
        fi
      done

      # Could be improved, lots of repeated logic
      if [[ "$valid_port" = "true" || "$valid_name" = "true" ]]; then
        mapfile -t -O "${#rulelist[@]}" rulelist < <(echo "$append")
        echo -e "Added rule ${YELLOW}${append}${NC} to rulelist"
      else
        echo -e "${RED}Invalid input${NC}"
      fi
      service="" protocol="" valid_port="false" valid_name="false" append=""
    done
  }

  fw_delete_rules() {
    echo "Not yet implemented."
    return 0
  }

  fw_finalize_rules() {
    if [[ "${#rulelist[@]}" -le 0 ]]; then
      print_status message error "Rulelist is empty, add rules, then try again"
      return 1
    fi

    if [[ ! "${active_firewall}" =~ ^(firewalld|ufw|nftables|iptables)$ ]]; then
      print_status message error "Unrecognized firewall"
      return 1
    fi

    clear
    local rule=""
    local reply=""
    echo -e "Please confirm this information is correct:"
    echo -e "${YELLOW}Firewall: ${RED}${active_firewall}${NC}"
    echo -e "${YELLOW}Inbound Allowed ports:"
    for rule in "${rulelist[@]}"; do
      printf "${RED}%s ${NC}" "$rule"
    done
    echo -e ""
    if [[ "$active_firewall" = "firewalld" ]]; then
      local interface=""
      local interfaces
      mapfile -t interfaces < <(ip -o link show | awk -F': ' '{print $2}' \
        | grep -qvE '^(lo|docker.*|br-.*|podman.*|tun.*|tap.*|wg.*|veth.*|tailscale.*)$')
      echo -e "${YELLOW}Interfaces:"
      for interface in "${interfaces[@]}"; do
        printf "${YELLOW}%s ${NC}" "$interface"
      done
      interface=""
      echo -e ""
    fi
    echo -e "${RED}Is this information correct? (y/n)?${NC}"
    while true; do
      read -rp "(y/n): " reply
      case $reply in
        y) reply="" && break ;;
        n)
          echo -e "${RED}Bringing you back to the menu...${NC}"
          return 0
          ;;
        *) echo -e "${RED}Unrecognized option, try again${NC}" && reply="" ;;
      esac
    done

    clear
    echo -e "${RED}${BOLD}FINAL WARNING: This will write to your firewall configuration if you continue.${NC}"
    echo -e "${RED}${BOLD}Default policy for input and output will be set to drop after this configuration finishes.${NC}"
    echo -e "Please double check to confirm this information is correct:"
    echo -e "${YELLOW}Firewall: ${RED}${active_firewall}${NC}"
    echo -e "${YELLOW}Inbound Allowed ports:"
    for rule in "${rulelist[@]}"; do
      printf "${RED}%s ${NC}" "$rule"
    done
    echo -e ""
    if [[ "$active_firewall" = "firewalld" ]]; then
      echo -e "${YELLOW}Interfaces:"
      for interface in "${interfaces[@]}"; do
        printf "${YELLOW}%s ${NC}" "$interface"
      done
    fi
    echo -e ""
    echo -e "${RED}Once more: Is this information correct? (y/n)?"
    while true; do
      read -rp "(y/n): " reply
      case $reply in
        y) reply="" && break ;;
        n)
          echo -e "${RED}Bringing you back to the menu...${NC}"
          return 0
          ;;
        *) echo -e "${RED}Unrecognized option, try again${NC}" && reply="" ;;
      esac
    done
    clear
    local rule
    local port
    local protocol
    echo -e "${RED}Applying rules to ${active_firewall}${NC}"
    # There is no default drop policy for output packets on firewalld,
    # therefore rich rules have to be used
    if [[ "$active_firewall" = "firewalld" ]]; then
      {
        firewall-cmd --new-zone=hardened --permanent
        firewall-cmd --zone=hardened --set-target=DROP --permanent
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv4 direction="out" drop'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv6 direction="out" drop'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv4 direction="out" port port="443" protocol="tcp" accept'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv4 direction="out" port port="80" protocol="tcp" accept'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv4 direction="out" port port="53" protocol="udp" accept'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv6 direction="out" port port="443" protocol="tcp" accept'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv6 direction="out" port port="80" protocol="tcp" accept'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv6 direction="out" port port="53" protocol="udp" accept'
        for rule in "${rulelist[@]}"; do
          port=$(echo "$rule" | cut -d "/" -f 1)
          protocol=$(echo "$rule" | cut -d "/" -f 2)
          firewall-cmd --add-port="${port}/${protocol}"
        done
        for interface in "${interfaces[@]}"; do
          firewall-cmd --zone=hardened --add-interface="$interface" --permanent
        done
        firewall-cmd --set-default-zone=hardened
      } || {
        printf "${RED}${BOLD}%s${NC}" "Something went wrong, exiting..."
        return 1
      }

    elif [[ "$active_firewall" = "ufw" ]]; then
      {
        for rule in "${rulelist[@]}"; do
          port=$(echo "$rule" | cut -d "/" -f 1)
          protocol=$(echo "$rule" | cut -d "/" -f 2)
          ufw allow in "${port}/${protocol}"
        done
        ufw allow out 443/tcp
        ufw allow out 80/tcp
        ufw allow out 53/udp
        ufw default deny incoming
        ufw default deny outgoing
      } || {
        printf "${RED}${BOLD}%s${NC}" "Something went wrong, exiting..."
        return 1
      }

    elif [[ "$active_firewall" = "nftables" ]]; then
      if ! nft list table inet filter &>/dev/null; then
        printf "${RED}%s${YELLOW}%s${NC}" \
          "table inet filter Not Found, please ensure you ran" "fwconf"
        return 1
      fi
      if ! nft list chain inet filter INPUT &>/dev/null \
        && ! nft list chain inet filter OUTPUT &>/dev/null \
        && ! nft list chain inet filter FORWARD &>/dev/null; then
        printf "${RED}%s${YELLOW}%s${NC}" \
          "Chain for INPUT, OUTPUT, or FORWARD was not found. Please ensure you ran" \
          "fwconf"
        return 1
      fi
      {
        for rule in "${rulelist[@]}"; do
          port=$(echo "$rule" | cut -d "/" -f 1)
          protocol=$(echo "$rule" | cut -d "/" -f 2)
          nft add rule inet filter INPUT "$protocol" dport "$port" accept
        done
        nft add rule inet filter OUTPUT tcp dport 443 accept
        nft add rule inet filter OUTPUT tcp dport 80 accept
        nft add rule inet filter OUTPUT udp dport 53 accept
        nft chain inet filter INPUT '{ policy drop; }'
        nft chain inet filter OUTPUT '{ policy drop; }'
        if [[ "$DISTRO" =~ ^(centos|rocky|almalinux|fedora|rhel|ol|opensuse.*)$ ]]; then
          nft list ruleset >/etc/sysconfig/nftables.conf
        elif [[ "$DISTRO" =~ ^(ubuntu|debian|arch)$ ]]; then
          nft list ruleset >/etc/nftables.conf
        else
          print_status message_alt warn \
            "Distribution could not be determined, placing in both" \
            "/etc/nftables.conf and /etc/sysconfig/nftables.conf"
          printf "%b%s%b and %b%s%b\n" \
            "$CYAN" "/etc/nftables.conf" "$NC" \
            "$CYAN" "/etc/sysconfig/nftables.conf" "$NC"
          nft list ruleset \
            | tee /etc/nftables.conf /etc/sysconfig/nftables.conf > /dev/null
        fi
      } || {
        printf "${RED}${BOLD}%s${NC}" "Something went wrong, exiting..."
        return 1
      }

    elif [[ "$active_firewall" = "iptables" ]]; then
      # You are supposed to flush, then set policy, then rules,
      # all to avoid packet losses, but we are ignoring that luxury
      {
        for rule in "${rulelist[@]}"; do
          port=$(echo "$rule" | cut -d "/" -f 1)
          protocol=$(echo "$rule" | cut -d "/" -f 2)
          iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT
          ip6tables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT
        done
        iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
        iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
        iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
        ip6tables -A OUTPUT -p tcp --dport 443 -j ACCEPT
        ip6tables -A OUTPUT -p tcp --dport 80 -j ACCEPT
        ip6tables -A OUTPUT -p udp --dport 53 -j ACCEPT
        iptables -P INPUT DROP
        iptables -P OUTPUT DROP
        ip6tables -P INPUT DROP
        ip6tables -P OUTPUT DROP
        iptables-save >/etc/iptables/rules.v4
        ip6tables-save >/etc/iptables/rules.v6
      } || {
        printf "${RED}${BOLD}%s${NC}" "Something went wrong, exiting..."
        return 1
      }
    else
      printf "${RED}${BOLD}%s${NC}" "Something went wrong, exiting..."
      exit 1
    fi
  }

  # Check firewall being used on the system
  local active_firewall=""
  if [[ " ${FIREWALLS[*]} " =~ " firewalld " && $DISTRO =~ ^(centos|rocky|almalinux|fedora|rhel|ol)$ ]]; then
    active_firewall="firewalld"
  elif [[ " ${FIREWALLS[*]} " =~ " ufw " && $DISTRO =~ ^(ubuntu|debian)$ ]]; then
    active_firewall="ufw"
  elif [[ " ${FIREWALLS[*]} " =~ " nftables " ]]; then
    active_firewall="nftables"
  elif [[ " ${FIREWALLS[*]} " =~ " iptables " ]]; then
    active_firewall="iptables"
  else
    echo -e "${RED}Unrecognized firewall.${NC}"
    return 0
  fi

  local -ar service_ports=(
    ftp-data:20/tcp
    ftp:21/tcp
    ssh:22/tcp
    smtp:25/tcp
    dns:53/udp # tcp also valid
    dhcp:67/udp
    dhcp-client:68/udp
    tftp:69/udp
    http:80/tcp
    kerberos:88/tcp # udp also valid
    pop3:110/tcp
    ntp:123/udp
    netbios-ns:137/udp
    netbios-dgm:138/udp
    netbios-ssn:139/tcp
    imap:143/tcp
    snmp:161/udp
    snmp-trap:162/udp
    ldap:389/tcp  # udp also valid
    https:443/tcp # udp also valid
    samba:445/tcp
    smpts:465/tcp
    syslog:514/udp
    dhcpv6-client:546/udp
    dhcpv6:547/udp
    ldaps:636/tcp # udp also valid
    ftps-data:989/tcp
    ftps:990/tcp
    imaps:993/tcp
    pops:995/tcp
    mysql:3306/tcp
    rdp:3389/tcp # udp also valid
    vnc:5900/tcp
  )

  local rulelist=()
  fw_help
  printf "%bConfiguring%b %b%s%b%b...%b\n" \
    "$GREEN" "$NC" \
    "$RED" "$active_firewall" "$NC" \
    "$GREEN" "$NC"
  printf \
    "%bIf%b %b%s%b %bis not the correct firewall, enter%b %bq%b %bbelow to cancel the configuration process%b\n" \
    "$GREEN" "$NC" \
    "$RED" "$active_firewall" "$NC" \
    "$GREEN" "$NC" \
    "${YELLOW}${BOLD}" "$NC" \
    "$GREEN" "$NC"
  while true; do
    read -rp "Enter command (h|q|a|s|l|d|r|f): "
    case "$REPLY" in
      help | h)
        fw_help
        ;;
      quit | exit | q | ex)
        clear
        return 0
        ;;
      append | a)
        fw_add_rules
        clear
        ;;
      list | l)
        local service=""
        for service in "${service_ports[@]}"; do
          echo -ne "${YELLOW}${service}${NC} "
        done
        echo -e ""
        ;;
      show | s)
        local rule=""
        for rule in "${rulelist[@]}"; do
          echo -ne "${YELLOW}${rule}${NC} "
        done
        echo -e ""
        ;;
      delete | d)
        fw_delete_rules
        ;;
      reset | r)
        rulelist=()
        echo -e "${YELLOW}Reset rulelist${NC}"
        ;;
      finalize | f)
        fw_finalize_rules
        ;;
      *)
        echo -e "${RED}Unrecognized option${NC}"
        REPLY=""
        ;;
    esac
  done
}

# CIS 6.2.3 (Ubuntu), 6.3.3 (RHEL)
configure_auditd() {
  if ! command -v auditctl; then
    print_status message error "Please ensure auditd is installed"
    return 1
  fi
  if [[ ! -f /etc/audit/auditd.conf ]]; then
    print_status not_found error file "/etc/audit/auditd.conf"
    return 1
  fi
  if [[ ! -d /etc/audit/rules.d || -f /etc/audit/rules.d/99-hardening.rules ]]; then
    print_status not_found error directory "/etc/audit/rules.d"
    return 1
  fi
  if [[ -f /etc/audit/rules.d/99-hardening.rules ]]; then
    print_status already_exists error file "99-hardening.rules"
    return 1
  fi

  # 6.2.2 (Ubuntu), 6.3.2 (RHEL)
  print_status message_object info file "Configuring" "/etc/audit/auditd.conf"
  if grep -qE \
    "^[[:blank:]]*max_log_file[[:blank:]]+=[[:blank:]]+[0-9]+$" \
    /etc/audit/auditd.conf; then
    if ! grep -qE \
      "^[[:blank:]]*max_log_file[[:blank:]]+=[[:blank:]]+([8-9]|[1-9][0-9]{1,2}|1000)$" \
      /etc/audit/auditd.conf; then
      sed -iE \
        's/^[[:blank:]]*max_log_file[[:blank:]]+=[[:blank:]]+[0-9]+$/max_log_file = 8/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "max_log_file = 8" >> /etc/audit/auditd.conf
  fi
  if grep -qiE \
    "^[[:blank:]]*max_log_file_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$" \
    /etc/audit/auditd.conf; then
    if ! grep -qiE \
      "^[[:blank:]]*max_log_file_action[[:blank:]]+=[[:blank:]]+keep_logs$" \
      /etc/audit/auditd.conf; then
      sed -iE \
        's/^[[:blank:]]*max_log_file_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/max_log_file_action = keep_logs/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
  fi
  # We explicitly do not follow the CIS Security Benchmark recommendations here,
  # disk_full_action = halt|single results in a loss of availability
  if grep -qiE \
    "^[[:blank:]]*disk_full_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*disk_full_action[[:blank:]]+=[[:blank:]]+(syslog|rotate)$"; then
      sed -iE \
        's/^[[:blank:]]*disk_full_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/disk_full_action = rotate/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "disk_full_action = rotate" >> /etc/audit/auditd.conf
  fi
  if grep -qiE \
    "^[[:blank:]]*disk_error_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*disk_error_action[[:blank:]]+=[[:blank:]]+syslog$"; then
      sed -iE \
        's/^[[:blank:]]*disk_error_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/disk_error_action = syslog/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "disk_error_action = syslog" >> /etc/audit/auditd.conf
  fi
  # Once again explicitly not following CIS Security Benchmarks
  # space_left_action|admin_space_left_action = halt|single
  # Either values result in a loss of availability.
  if grep -qiE \
    "^[[:blank:]]*space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*space_left_action[[:blank:]]+=[[:blank:]]+(email|rotate)$"; then
      sed -iE \
        's/^[[:blank:]]*space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/space_left_action = email/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "space_left_action = email" >> /etc/audit/auditd.conf
  fi
  if grep -qiE \
    "^[[:blank:]]*admin_space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$"; then
    if ! grep -qiE \
      "^[[:blank:]]*admin_space_left_action[[:blank:]]+=[[:blank:]]+(email|rotate)$"; then
      sed -iE \
        's/^[[:blank:]]*admin_space_left_action[[:blank:]]+=[[:blank:]]+[[:word:]]+$/admin_space_left_action = email/' \
        /etc/audit/auditd.conf
    fi
  else
    echo "admin_space_left_action = email" >> /etc/audit/auditd.conf
  fi
  print_status message_object success file \
    "Finished configuring" "/etc/audit/auditd.conf"

  print_status message_object info file \
    "Adding rules to" "/etc/audit/rules.d/99-hardening.rules"
  cat <<'EOF' | tee /etc/audit/rules.d/99-hardening.rules
# These rules were added by Michael's Linux Hardening Script

# 6.2.3.1/6.3.3.1
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# 6.2.3.2/6.3.3.2
-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation
-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation

# 6.2.3.3/6.3.3.3
-w /var/log/sudo.log -p wa -k sudo_log_file

# 6.2.3.4/6.3.3.4
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change

# 6.2.3.5/6.3.3.5 (partial)
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale

# 6.2.3.6/6.3.3.6
# Not yet implemented

# 6.2.3.7/6.3.3.7
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

# 6.2.3.8/6.3.3.8
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity

# 6.2.3.9/6.3.3.9
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod

# 6.2.3.10/6.3.3.10
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

# 6.2.3.11/6.3.3.11
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# 6.2.3.12/6.3.3.12
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# 6.2.3.13/6.3.3.13
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

# 6.2.3.15/6.3.3.15
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.2.3.16/6.3.3.16
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.2.3.17/6.3.3.17
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng

# 6.2.3.18/6.3.3.18
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod

# 6.2.3.19/6.3.3.19
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules

EOF
  case "$DISTRO" in
    ubuntu | debian)
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
# 6.2.3.5 (Ubuntu)
-w /etc/networks -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale

# 6.2.3.14 (Ubuntu)
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# 6.2.3.20
-e 2
EOF
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
# 6.3.3.5 (RHEL)
-w /etc/hostname -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/NetworkManager -p wa -k system-locale

# 6.3.3.14 (RHEL)
-w /etc/selinux -p wa -k MAC-policy
-w /usr/share/selinux -p wa -k MAC-policy

# 6.3.3.20
-e 2
EOF
      ;;
    opensuse*)
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
# 6.3.3.5 (SUSE)
-w /etc/hostname -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/NetworkManager -p wa -k system-locale

# 6.3.3.14 (SUSE)
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# 6.3.3.20
-e 2
EOF
      ;;
    *)
      tee -a /etc/audit/rules.d/99-hardening.rules <<'EOF'
# 6.2.3.20/6.3.3.20
-e 2
EOF
      ;;
  esac
  augenrules --load
  augenrules --check
  systemctl enable --now auditd
}

configure_logging() {
  return 0
}

configure_aide() {
  command -v aide &>/dev/null || {
    print_status message error "Please ensure AIDE is installed."
    return 1
  }
  case "$DISTRO" in
    ubuntu | debian)
      aideinit
      mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      ;;
    centos | rocky | almalinux | fedora | rhel | ol)
      aide --init
      mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
      ;;
    *)
      print_status message error \
        "Unsupported distribution, cannot configure"
      return 1
      ;;
  esac
  systemctl enable --now dailyaidecheck.timer
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
# CIS Ubuntu 12: 1.1.1.1-5,8-9, 3.2
# 1.1.1.10 to be added
# Will disable unnecessary kernel modules
disable_kernel_modules() {
  local -a modules=(
    "cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage"
    "dccp" "tipc" "rds" "sctp"
  )
#  local -a extra_modules=(
#    "afs" "ceph" "cifs" "exfat" "ext" "fat" "fscache" "fuse" "gfs2"
#    "nfs_common" "nfsd" "smbfs_common"
#  )
  if "$DISTRO" != "ubuntu" && ! command -v snap; then
    modules+=("squashfs")
  fi
  local hardening_blacklist="/etc/modprobe.d/hardening-blacklist.conf"
  touch "$hardening_blacklist"
  local mod
  # Check for duplicates entries, then add an entry if it doesn't exist.
  for mod in "${modules[@]}"; do
    if ! grep -qE "^install[[:blank:]]+${mod}[[:blank:]]+" "$hardening_blacklist"; then
      echo "install $mod /bin/false" >>"$hardening_blacklist"
    fi
  done
}

# Configure sysctl parameters to harden the system
# CIS Ubuntu 12: 3.1.1
configure_sysctl() {
  local disable_ipv6="false"
  local sysctl_file="/etc/sysctl.d/99-hardening.conf"
  local limits_file="/etc/security/limits.d/99-hardening.conf"

  local arg=""
  for arg in "$@"; do
    case "$arg" in
      disable_ipv6=true) disable_ipv6="true" ;;
      disable_ipv6=false) disable_ipv6="false" ;;
      *)
        echo "Unrecognized argument: $arg" >&2
        return 1
        ;;
    esac
  done

  declare -A settings=(
    ["kernel.randomize_va_space"]="2"
    ["kernel.yama.ptrace_scope"]="2"
    ["fs.suid_dumpable"]="0"
    ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.conf.all.rp_filter"]="2"
    ["net.ipv4.conf.default.rp_filter"]="2"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.conf.default.log_martians"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
  )

  if [ $disable_ipv6 = "true" ]; then
    settings["net.ipv6.conf.all.disable_ipv6"]="0"
  fi

  if [ ! -d "/etc/sysctl.d" ]; then
    print_status not_found error directory "/etc/sysctl.d"
    return 1
  fi
  if [ -f "$sysctl_file" ]; then
    print_status already_exists error file "$sysctl_file" kind
    return 1
  fi

  # This simply iterates through each element and appends it to the file,
  # Additionally it sets it up via sysctl.
  local value
  for key in "${!settings[@]}"; do
    value="${settings[$key]}"
    echo "${key} = ${value}" >>"$sysctl_file"
    sysctl -w "${key}=${value}" &>/dev/null
  done

  if [ ! -d "/etc/security/limits.d" ]; then
    print_status not_found error directory "/etc/security/limits.d"
    return 1
  fi
  if [ -f "$limits_file" ]; then
    print_status already_exists error file "$sysctl_file" kind
    return 1
  fi
  # Disable core dumps
  echo "* hard core 0" > "$limits_file"
}

# Will change boot parameters and ensure MAC is enforced
configure_grub() {
  if command -v grubby; then
    grubby --update-kernel ALL --remove-args "selinux=0 enforcing=0"
    grubby --update-kernel="$(grubby --default-kernel)" \
      --args="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"
    print_status message success "Reconfigured GRUB successfully"
    return 0
  fi

  if [[ ! -f /etc/default/grub ]]; then
    print_status not_found error file "/etc/default/grub"
    return 1
  fi

  if grep -qE '^[[:blank:]]*GRUB_CMDLINE_LINUX="[[:blank:]]*"$' /etc/default/grub; then
    sed -i -E \
      's/^[[:blank:]]*GRUB_CMDLINE_LINUX="[[:blank:]]*"$/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"/' \
      /etc/default/grub
  elif grep -qE '^[[:blank:]]*GRUB_CMDLINE_LINUX=".*"$' /etc/default/grub; then
    sed -i -E \
      's/^[[:blank:]]*(GRUB_CMDLINE_LINUX=".*)"/\1 apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"/' \
      /etc/default/grub
  elif ! grep -qE '^[[:blank:]]*GRUB_CMDLINE_LINUX=".*"$' /etc/default/grub; then
    echo GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192" >>/etc/default/grub
  else
    print_status message_alt error \
      "Failed to append to " "/etc/default/grub"
    printf "%b%s%b" "$YELLOW" "/etc/default/grub" "$NC"
    return 1
  fi

  if grep -qE 'selinux=0|enforcing=0' /etc/default/grub; then
    sed -i 's/\bselinux=0\b//g; s/\benforcing=0\b//g' /etc/default/grub
  fi

  if command -v update-grub; then
    update-grub
  elif command -v grub2-mkconfig && [[ -f /boot/grub2/grub.cfg ]]; then
    grub2-mkconfig -o /boot/grub2/grub.cfg
  else
    print_status message error "Please manually run update-grub"
    return 1
  fi

  print_status message success "Reconfigured GRUB successfully"
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

  { [[ -f $HOME/.env ]] && . "$HOME/.env" &>/dev/null; } \
    || print_status message info "Couldn't find .env file, skipping..."
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
