#!/usr/bin/env bash

# The following status messages are available
# print_status message status "text"
# print_status message_object status object "text" "object"
# print_status message_alt status
# print_status not_found status object "path"
# print_status already_exists status
# print_status using_to status
# print_status not_installed status
# print_status invalid_input status "text"
# print_status unrecognized_option status
# print_status found_in status
# print_status duplicate_found_in status
# print_status unsuccessful_function status


# Helper function to print status messages
# print_status status_message status "..."
print_status() {
  local name="$1"
  shift
  "prst_${name}" "$@" || printf "%b%s%b\n" "$UC" "Unknown Error" "$UC"
}

# Generic status message
# print_status message status "text"
prst_message() {
  local input_status="${1:-unknown}"
  local input_text="${2:-unknown}"
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
  local input_status="${1:-unknown}"
  local input_object="${2:-unknown}"
  local input_text="${3:-unknown}"
  local object_text="${4:-unknown}"
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
    firewall) local object="$object_text" object_color="${RED}${BOLD}" ;;
    *) local object="$object_text" object_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$input_text" "$NC" \
    "$object_color" "$object" "$NC"
}

# Will replace prst_message_alt
prst_message_multiobject() {
  return 0
}

# Not found status message
# print_status not_found status object "path"
prst_not_found() {
  local input_status="${1:-unknown}"
  local input_object="${2:-unknown}"
  local input_path="${3:-unknown}"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  case "$input_object" in
    file) local object="file" object_color="${CYAN}${BOLD}" ;;
    directory) local object="directory" object_color="${MAGENTA}${BOLD}" ;;
    command) local object="command" object_color="${YELLOW}${BOLD}" ;;
    *) local object="$input_object" object_color="${UC}${BOLD}" ;;
  esac
  printf "%b[%s]%b %b%s not found:%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$object" "$NC" \
    "$object_color" "$input_path" "$NC"
}

# Already Exists status message
# print_status already_exists "error|warn" "file|directory|*" "input" "kind|rude"
prst_already_exists() {
  local input_status="${1:-unknown}"
  local input_object="${2:-unknown}"
  local input_path="${3:-unknown}"
  local kindness="${4:-unknown}"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  case "$input_object" in
    file) local object="file" object_color="${CYAN}${BOLD}" ;;
    directory) local object="directory" object_color="${MAGENTA}${BOLD}" ;;
    command) local object="command" object_color="${YELLOW}${BOLD}" ;;
    rule) local object="rule" object_color="${YELLOW}${BOLD}" ;;
    *) local object="$input_object" object_color="${UC}${BOLD}" ;;
  esac
  printf "%b[%s]%b %b%s already exists:%b %b%s%b%b" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$object" "$NC" \
    "$object_color" "$input_path" "$NC" "$text_color"
  case "$kindness" in
    kind) printf ", Please remove it if you would like to try again%b\n" \
      "$NC" ;;
    rude | *) printf "%b\n" "$NC" ;;
  esac
}

# using "package-manager" to install "package"
# print_status using_to status "action" "package-manager" "package"
prst_using_to() {
  local input_status="${1:-unknown}"
  local input_action="${2:-unknown}"
  local input_package_manager="${3:-unknown}"
  local input_package="${4:-unknown}"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  case "$input_action" in
    install) local action="install" ;;
    remove) local action="remove" ;;
    upgrade) local action="upgrade" && input_package="the system" ;;
    *) local action="$input_action" ;;
  esac
  printf "%b[%s]%b %bUsing%b %b%s%b %bto %s%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$NC" \
    "$YELLOW" "$input_package_manager" "$NC" \
    "$text_color" "$action" "$NC" \
    "$YELLOW" "$input_package" "$NC"
}

# Not installed: package status message
# print_status not_installed status "package"
prst_not_installed() {
  local input_status="${1:-unknown}"
  local input_package="${2:-unknown}"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b: %bnot installed%b\n" \
    "$status_color" "$status" "$NC" \
    "$YELLOW" "$input_package" "$NC" \
    "$text_color" "$NC"
}
# Invalid input status message
# print_status invalid_input "error|info" "input"
prst_invalid_input() {
  local input_status="${1:-unknown}"
  local input_action="${2:-unknown}"
  case "$input_status" in
    error)
      printf "%b[ERROR]%b %bInvalid input:%b %b%s%b\n" "$EC" "$NC" "$RED" "$NC" "$RED" "$input_action" "$NC"
      ;;
    info)
      printf "%b[INFO]%b %bInvalid input:%b %b%s%b\n" "$IC" "$NC" "$BLUE" "$NC" "$BLUE" "$input_action" "$NC"
      ;;
    *)
      printf "Invalid input: %s\n" "$input_action"
      ;;
  esac
}

# Unrecognized option status message
# print_status unrecognized_option status "input" rude|kind
prst_unrecognized_option() {
  local input_status="${1:-unknown}"
  local input_text="${2:-unknown}"
  local kindness="${3:-unknown}"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %bUnrecognized option:%b %b%s%b" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$NC" \
    "${YELLOW}${BOLD}" "$input_text" "$NC"
  case "$kindness" in
    kind) printf "%b, please try again.%b\n" "$text_color" "$NC" ;;
    rude | *) printf "%b, try again.%b\n" "$text_color" "$NC" ;;
  esac
}

# object found in file alert message
# print_status found_in alert "input" "path"
prst_found_in() {
  local input_status="${1:-unknown}"
  local input_text="${2:-unknown}"
  local input_path="${3:-unknown}"
  case "$input_status" in
    *) local status="ALERT" status_color="$EC" text_color="$EC" ;;
  esac
  printf "%b[%s]%b %b%s%b %bfound in%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "${YELLOW}${BOLD}" "$input_text" "$NC" \
    "$text_color" "$NC" \
    "$CYAN" "$input_path" "$NC"
}

# Duplicate object found in file alert message
# print_status duplicate_found_in alert "input" "path"
prst_duplicate_found_in() {
  local input_status="${1:-unknown}"
  local input_text="${2:-unknown}"
  local input_path="${3:-unknown}"
  case "$input_status" in
    *) local status="ALERT" status_color="$EC" text_color="$EC" ;;
  esac
  printf "%b[%s]%b %bDuplicate%b %b%s%b %bfound in%b %b%s%b\n" \
    "$status_color" "$status" "$NC" \
    "$text_color" "$NC" \
    "${YELLOW}${BOLD}" "$input_text" "$NC" \
    "$text_color" "$NC" \
    "$CYAN" "$input_path" "$NC"
}

# print_status unsuccessful_function "error|warn" "function"
prst_unsuccessful_function() {
  local input_status="${1:-unknown}"
  local input_text="${2:-unknown}"
  case "$input_status" in
    error) local status="ERROR" status_color="$EC" text_color="$RED" ;;
    warn) local status="WARN" status_color="$WC" text_color="$YELLOW" ;;
    info) local status="INFO" status_color="$IC" text_color="$BLUE" ;;
    success) local status="SUCCESS" status_color="$SC" text_color="$GREEN" ;;
    alert) local status="ALERT" status_color="$EC" text_color="$EC" ;;
    *) local status="UNKNOWN" status_color="$UC" text_color="$UC" ;;
  esac
  printf "%b[%s]%b %b%s%b %bdid not complete successfully%b\n" \
    "$status_color" "$status" "$NC" \
    "${YELLOW}${BOLD}" "$input_text" "$NC" \
    "$text_color" "$NC"
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