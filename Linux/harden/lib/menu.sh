#!/usr/bin/env bash

# Because we preferably would like to keep compatibility with Bash 4.0,
# namerefs cannot be used. Instead, a function to generate menus, using
# hardcoded values for certain arrays has to be used

# Generates options for a menu
generate_menu_options() {
  if [[ -z "$1" ]]; then
    print_status message error "Empty root"
    return 1
  elif [[ -z "$2" ]]; then
    print_status message error "Empty sections"
    return 1
  fi
  local root="$1" root_section section option short_option description cache=""
  local -a sections options
  local -i val=0
  shift
  while [[ "$#" -ge 1 ]]; do
    mapfile -t -O "$val" sections < <(echo "$1")
    val+=1
    shift
  done
  generate_menu_options_array

  for section in "${sections[@]}"; do
    root_section="${root}:${section}"

    if [[ "${_UN_GENERATE_MENU_OPTIONS["${root_section}:HEADER"]}" == "true" ]]; then
      printf "\n%b%-17s%b:\t%s\n" \
        "${GREEN}${BOLD}" \
        "${_UN_GENERATE_MENU_OPTIONS["${root_section}:NAME"]}" \
        "${GREEN}" \
        "${_UN_GENERATE_MENU_OPTIONS["${root_section}:DESCRIPTION"]}"
    elif [[ "${_UN_GENERATE_MENU_OPTIONS["${root_section}:HEADER"]}" == "" ]]; then
      print_status message error "HEADER missing"
      return 1
    fi

    IFS=':' read -ra options \
      <<<"${_UN_GENERATE_MENU_OPTIONS["${root_section}:PRINT_ORDER"]}"
    for option in "${options[@]}"; do
      if [[ -z "${_UN_GENERATE_MENU_OPTIONS["${root_section}:${option}"]:-}" ]]; then
        continue # TODO: make this NOT silently fail
      fi
      short_option="${_UN_GENERATE_MENU_OPTIONS["${root_section}:${option}"]%%:*}"
      description="${_UN_GENERATE_MENU_OPTIONS["${root_section}:${option}"]##*:}"
      if [[ ! -z "$short_option" ]]; then
        short_option="${short_option} | "
      fi
      printf "%b%-17s%b:\t%s\n" \
        "${YELLOW}${BOLD}" "${short_option}${option}" "${NC}" \
        "${description}"
    done
  done
  __MENU_MAIN_CACHE="$cache"
  echo -e "$__MENU_MAIN_CACHE"
  unset _UN_GENERATE_MENU_OPTIONS
}

generate_headers() {
  :
}

# A workaround for compatibility reasons, assigns a "global" associative array
# for use by generate_menu_options. It contains the actual values used to
# generate a menu. Variables prefixed with _UN_ indicate that they should be
# unset after they are no longer needed

generate_menu_options_array() {
  declare -gA _UN_GENERATE_MENU_OPTIONS=(
    ["main:tools:HEADER"]="true"
    ["main:tools:NAME"]="Tools"
    ["main:tools:DESCRIPTION"]="Useful for operation of the script"
    ["main:tools:PRINT_ORDER"]="backup:init:pms:pscf:pscs:ssc:bash:quit"
    ["main:tools:backup"]="b:Will backup \"important directories\""
    ["main:tools:init"]="i:Show initial information gathered at beginning of the script"
    #["main:tools:pms"]="p:Poor Man's SIEM"
    ["main:tools:pscf"]="f:ps command, with detailed output"
    ["main:tools:pscs"]="S:ps command, with simplified output"
    ["main:tools:ssc"]="s:ss command, excluding localhost"
    ["main:tools:bash"]="B:Enter a bash login shell within the script"
    ["main:tools:quit"]="q:Exit program"

    ["main:packages:HEADER"]="true"
    ["main:packages:NAME"]="Packages"
    ["main:packages:DESCRIPTION"]="Automated upgrades, removals, and installations"
    ["main:packages:PRINT_ORDER"]="upgrade:remove:install:download"
    ["main:packages:upgrade"]="up:Upgrades the system"
    ["main:packages:remove"]="rm:Asks to remove potentially unwanted packages"
    ["main:packages:install"]="in:Asks to install potentially helpful packages"
    ["main:packages:download"]="dl:Asks to download third-party software"

    ["main:quick:HEADER"]="true"
    ["main:quick:NAME"]="Quick"
    ["main:quick:DESCRIPTION"]="Run instantly + don't require package installs (usually)"
    ["main:quick:PRINT_ORDER"]="grub:perms:parts:mods:sys:mac"
    ["main:quick:grub"]=":Configures bootloader parameters"
    ["main:quick:perms"]=":Reconfigures permissions for files and directories"
    ["main:quick:parts"]=":Sets secure mount options for partitions"
    ["main:quick:mods"]=":Disables unused kernel modules"
    ["main:quick:sys"]=":Reconfigures kernel parameters"
    ["main:quick:mac"]=":Sets up AppArmor/SELinux"

    ["main:heavy:HEADER"]="true"
    ["main:heavy:NAME"]="Heavy"
    ["main:heavy:DESCRIPTION"]="May require package installs"
    ["main:heavy:PRINT_ORDER"]="fwinit:fwconf:logging:audit:aide"
    ["main:heavy:fwinit"]="fwi:Initializes the firewall on the system"
    ["main:heavy:fwconf"]="fwc:Helps you configure in/out firewall rules"
    ["main:heavy:logging"]="log:Initializes and configures journald or rsyslog"
    ["main:heavy:audit"]="aud:Initializes auditd configuration and rules"
    ["main:heavy:aide"]="aid:Initializes AIDE (may take awhile)"

    ["fw:help:HEADER"]="false"
    ["fw:help:PRINT_ORDER"]="append:toggle:delete:reset:show:list:finalize:help:quit"
    ["fw:help:append"]="a:Allows you to append allow inbound rules to rulelist"
    ["fw:help:toggle"]="t:Allows you to toggle allow outbound rules on rulelist"
    ["fw:help:delete"]="d:Will let you delete a specific inbound rule on rulelist"
    ["fw:help:reset"]="r:Will delete all of your rules on rulelist"
    ["fw:help:show"]="s:Will show your rulelist"
    ["fw:help:list"]="l:Will list available service names"
    ["fw:help:finalize"]="f:Will implement your rulelist onto the permanent firewall configuration"
    ["fw:help:help"]="h:Will show you this prompt again"
    ["fw:help:quit"]="q:Will quit to main menu, without saving any changes"
  )
}
