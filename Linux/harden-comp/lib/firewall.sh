#!/bin/bash

init_firewall() {
  # CIS Debian 12: 4.1
  if [ ${#FIREWALLS[@]} -eq 0 ]; then
    print_status message error "Please install a firewall onto the system, then try again."
    return 1
  fi

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
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
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
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
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
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
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
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
      return 1
    }
  else
    print_status message error "Unrecognized firewall"
    return 1
  fi
  touch .fwinit_ran
}

# User interactive function
configure_firewall() {
  if [ ${#FIREWALLS[@]} -eq 0 ]; then
    print_status message error "Ensure a firewall is installed on the system"
    return 1
  fi
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
    print_status message error "Unrecognized firewall"
    return 0
  fi

  local -a rulelist=()
  local -A outbound_rulelist=(
    ["http:80/tcp"]="ALLOW"
    ["https:443/tcp"]="ALLOW"
    ["dns:53/udp"]="ALLOW"
    ["ntp:123/udp"]="ALLOW"
    ["dns-xfr:53/tcp"]="DROP"
  )
  local -ar service_ports=(
    ftp-data:20/tcp
    ftp:21/tcp
    ssh:22/tcp
    smtp:25/tcp
    dns:53/udp
    dns-xfr:53/tcp
    dhcp:67/udp
    dhcp-client:68/udp
    tftp:69/udp
    http:80/tcp
    kerberos:88/udp
    kerberos-tcp:88/tcp
    pop3:110/tcp
    ntp:123/udp
    netbios-ns:137/udp
    netbios-dgm:138/udp
    netbios-ssn:139/tcp
    imap:143/tcp
    snmp:161/udp
    snmp-trap:162/udp
    ldap:389/tcp
    https:443/tcp
    https3:443/udp
    samba:445/tcp
    smpts:465/tcp
    syslog:514/udp
    dhcpv6-client:546/udp
    dhcpv6:547/udp
    ldaps:636/tcp
    ftps-data:989/tcp
    ftps:990/tcp
    imaps:993/tcp
    pops:995/tcp
    mysql:3306/tcp
    rdp:3389/tcp
    rdp-udp:3389/udp
    vnc:5900/tcp
  )

  fw_add_rules() {
    local service="" protocol="" valid_port="false" valid_name="false" append="" rule=""
    while true; do
      read -rp "Enter port/protocol or service name (q to exit): " service protocol
      # For verifying that given input is valid
      # Is input only numbers, then is it a valid port number, and finally
      # did they specify a valid protocol?
      if [[ "$service" =~ ^[0-9]+$ ]]; then
        if ((service >= 1 && service <= 65535)); then
          if [[ "$protocol" =~ ^(tcp|udp)$ ]]; then
            valid_port="true"
            append="${service}/${protocol}"
          fi
        fi
      # NaN? Lets check if they give a service name instead
      # Is input letters/dashes, ending with a letter or 1 digit?
      # Example: "pop3" and "ssh" will match, but not "prot42")
      elif [[ "$service" =~ ^[a-z-]+[a-z0-9]$ ]]; then
        local service_name=""
        local attempted_service=""
        # Does the input service exist in the service_ports array?
        for service_name in "${service_ports[@]}"; do
          attempted_service=$(echo "$service_name" | cut -d ":" -f 1)
          if [[ "$attempted_service" = "$service" ]]; then
            valid_name="true"
            append=$(echo "$service_name" | cut -d ":" -f 2)
          fi
        done
      elif [[ "$service" = "q" ]]; then # did they type q to exit?
        return 0
      else
        print_status invalid_input error "$service"
        service=""
        protocol=""
        valid_port="false"
        valid_name="false"
        append=""
        continue
      fi

      # Is the rule already in the rulelist?
      for rule in "${rulelist[@]}"; do
        if [[ "$rule" == "$append" ]]; then
          echo -e "${RED}Rule already exists.${NC}"
          service=""
          protocol=""
          valid_port="false"
          valid_name="false"
          append=""
          continue 2
        fi
      done

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

  fw_show_outbound() {
    for outbound_service in "${!outbound_rulelist[@]}"; do
      if [[ "${outbound_rulelist[$outbound_service]}" == "ALLOW" ]]; then
        printf "%-15s : %b%7s%b\n" \
          "$outbound_service" "${GREEN}${BOLD}" "ALLOW" "$NC"
      else
        printf "%-15s : %b%7s%b\n" \
          "$outbound_service" "${RED}${BOLD}" "DROP" "$NC"
      fi
    done
  }

  fw_toggle_outbound() {
    local outbound_service
    local service_name
    local reply
    while true; do
      jclr
      fw_show_outbound
      printf "%bq%b to exit\n" "${YELLOW}${BOLD}" "$NC"
      read -rp "Enter service name to toggle (q to exit): " reply
      case "$reply" in
        q)
          return 0
          ;;
        *)
          # TODO: excessive nesting, needs to be cleaned
          for outbound_service in "${!outbound_rulelist[@]}"; do
            service_name=$(echo "$outbound_service" | cut -d ":" -f 1)
            if [[ "$service_name" == "$reply" ]]; then
              if [[ "${outbound_rulelist[$outbound_service]}" == "DROP" ]]; then
                outbound_rulelist[$outbound_service]="ALLOW"
              else
                outbound_rulelist[$outbound_service]="DROP"
              fi
            fi
          done
          ;;
      esac
    done
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

    jclr
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
        print_status message error \
          "Something went wrong, attempting to restore backup..."
        restore_firewall || print_status message error "Backup restoration failed"
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
        print_status message error \
          "Something went wrong, attempting to restore backup..."
        restore_firewall || print_status message error "Backup restoration failed"
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
        print_status message error \
          "Something went wrong, attempting to restore backup..."
        restore_firewall || print_status message error "Backup restoration failed"
        return 1
      }
    else
      print_status message error \
        "Something went wrong, exiting..."
      exit 1
    fi
  }

  fw_help() {
    jclr
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "a | append" "Allows you to append allow inbound rules to rulelist"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "t | toggle" "Allows you to toggle allow outbound rules on rulelist"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "d | delete" "Will let you delete a specific inbound rule on rulelist"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "r | reset" "Will delete all of your rules on rulelist"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "s | show" "Will show your rulelist"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "l | list" "Will list available service names"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "f | finalize" "Will implement your rulelist onto the permanent firewall configuration"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "h | help" "Will show you this prompt again"
    printf "${YELLOW}${BOLD}%-10s${NC} :\t %s\n" "q | quit" "Will quit to main menu, without saving any changes"
    printf "\n"
    printf "Before rules are applied to the real firewall configuration,\n"
    printf \
      "they are added to your %brulelist%b, which can be viewed with %bs%b.\n" \
      "${YELLOW}${BOLD}" "$NC" \
      "${YELLOW}${BOLD}" "$NC"
    printf "%bf%b applies the rulelist to the real, " \
      "${YELLOW}${BOLD}" "$NC"
    printf "permanent firewall configuration.\n"
    printf "\nAcceptable Syntax Examples:\n"
    printf "Enter port/protocol or service name: 22 tcp\n"
    printf "Enter port/protocol or service name: ssh\n"
    printf "\n"
  }

  # Command prompt loop
  if [[ ! -e .fwinit_ran ]]; then
    print_status message_object alert command "Please ensure you ran" "fwinit"
    printf \
      "%bOtherwise, continue at your own discretion,\nstrange issues may occur%b\n\n" \
      "${RED}${BOLD}" "$NC"
  fi
  printf "%bWelcome to%b %bfwconf%b\n" \
    "$GREEN" "$NC" \
    "${YELLOW}${BOLD}" "$NC"
  printf "View help with %bh%b\n" "${YELLOW}${BOLD}" "$NC"
  print_status message_object warn firewall "Configuring" "$active_firewall"
  print_status message_object info command "Wrong firewall? Exit with" "q"
  while true; do
    read -rp "fwconf> "
    case "$REPLY" in
      help | h)
        fw_help
        ;;
      quit | exit | q | ex)
        jclr
        return 0
        ;;
      append | a)
        fw_add_rules
        ;;
      toggle | t)
        fw_toggle_outbound
        ;;
      list | l)
        local service=""
        for service in "${service_ports[@]}"; do
          printf "%b%s%b " "$YELLOW" "$service" "$NC"
        done
        printf "\n"
        ;;
      show | s)
        local rule=""
        for rule in "${rulelist[@]}"; do
          printf "%b%s%b " "$YELLOW" "$rule" "$NC"
        done
        printf "\n"
        fw_show_outbound
        ;;
      delete | d)
        fw_delete_rules
        ;;
      reset | r)
        rulelist=()
        print_status message success "Rulelist reset"
        ;;
      finalize | f)
        fw_finalize_rules
        ;;
      *)
        print_status unrecognized_option error "$REPLY" rude
        REPLY=""
        ;;
    esac
  done
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
  declare -gA FW_BACKUPS=()
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
      print_status message_object error file "Failed to restore" "$path"
      return 1
    }
  done
}
