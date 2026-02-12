#!/usr/bin/env bash

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
      systemctl disable --now nftables &> /dev/null || true
      systemctl disable --now netfilter-persistent &> /dev/null || true
      systemctl disable --now ufw &> /dev/null || true
      firewall-cmd --permanent --set-default-zone=public || true
      firewall-cmd --permanent --zone=trusted --add-interface=lo
      firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
      firewall-cmd --permanent --add-rich-rule='rule family=ipv6 source address="::1" destination not address="::1" drop'
    } || {
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
      return 1
    }
    systemctl enable --now firewalld || true
    firewall-cmd --reload || true

  elif [[ " ${FIREWALLS[*]} " =~ " ufw " && $DISTRO =~ ^(ubuntu|debian)$ ]]; then
    {
      print_status message info "Backing up configuration (if it exists)..."
      backup_firewall ufw init
      systemctl disable --now nftables &> /dev/null || true
      systemctl disable --now netfilter-persistent &> /dev/null || true
      systemctl disable --now firewalld &> /dev/null || true
      ufw allow in on lo
      ufw allow out on lo
      ufw deny in from 127.0.0.0/8
      ufw deny in from ::1
    } || {
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
      return 1
    }
      systemctl enable --now ufw || true
      ufw --force enable || true

  elif [[ " ${FIREWALLS[*]} " =~ " nftables " ]]; then
    {
      print_status message info "Backing up configuration (if it exists)..."
      backup_firewall nftables init
      systemctl disable --now netfilter-persistent &> /dev/null || true
      systemctl disable --now firewalld &> /dev/null || true
      systemctl disable --now ufw &> /dev/null || true
      nft list table inet filter &> /dev/null || nft create table inet filter
      nft list chain inet filter INPUT &> /dev/null || nft create chain inet filter INPUT '{ type filter hook input priority filter ; policy accept ; }'
      nft list chain inet filter FORWARD &> /dev/null || nft create chain inet filter FORWARD '{ type filter hook forward priority filter ; policy drop ; }'
      nft list chain inet filter OUTPUT &> /dev/null || nft create chain inet filter OUTPUT '{ type filter hook output priority filter ; policy accept ; }'
      nft add rule inet filter INPUT iif lo accept
      nft add rule inet filter INPUT ip saddr 127.0.0.0/8 counter drop
      nft add rule inet filter INPUT ip protocol tcp ct state established accept
      nft add rule inet filter INPUT ip protocol udp ct state established accept
      nft add rule inet filter OUTPUT oif lo accept
      nft add rule inet filter OUTPUT ip protocol tcp ct state related,established accept
      nft add rule inet filter OUTPUT ip protocol udp ct state related,established accept
      if [[ "$DISTRO" =~ ^(centos|rocky|almalinux|fedora|rhel|ol|sles|opensuse.*|suse)$ ]]; then
        nft list ruleset > /etc/sysconfig/nftables.conf
      elif [[ "$DISTRO" =~ ^(ubuntu|debian|arch)$ ]]; then
        nft list ruleset > /etc/nftables.conf
      else
        print_status message_alt warn "Distribution could not be determined, placing in both" "/etc/nftables.conf and /etc/sysconfig/nftables.conf"
        printf "%b%s%b and %b%s%b\n" "$CYAN" "/etc/nftables.conf" "$NC" "$CYAN" "/etc/sysconfig/nftables.conf" "$NC"
        nft list ruleset | tee /etc/nftables.conf /etc/sysconfig/nftables.conf >/dev/null
      fi
    } || {
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
      return 1
    }
      systemctl enable --now nftables

  elif [[ " ${FIREWALLS[*]} " =~ " iptables " ]]; then
    {
      print_status message info "Backing up configuration (if it exists)..."
      backup_firewall iptables init
      systemctl disable --now nftables &> /dev/null || true
      systemctl disable --now firewalld &> /dev/null || true
      systemctl disable --now ufw &> /dev/null || true
      iptables -F &> /dev/null || true
      iptables -P INPUT ACCEPT
      iptables -P OUTPUT ACCEPT
      iptables -P FORWARD DROP
      iptables -A INPUT -i lo -j ACCEPT
      iptables -A OUTPUT -o lo -j ACCEPT
      iptables -A INPUT -s 127.0.0.0/8 -j DROP
      iptables -A OUTPUT -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
      iptables -A OUTPUT -p udp -m state --state RELATED,ESTABLISHED -j ACCEPT
      iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
      iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
      iptables-save > /etc/iptables/rules.v4
      ip6tables -F &>/dev/null || true
      ip6tables -P INPUT ACCEPT
      ip6tables -P OUTPUT ACCEPT
      ip6tables -P FORWARD DROP
      ip6tables -A INPUT -i lo -j ACCEPT
      ip6tables -A OUTPUT -o lo -j ACCEPT
      ip6tables -A INPUT -s ::1 -j DROP
      ip6tables -A OUTPUT -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
      ip6tables -A OUTPUT -p udp -m state --state RELATED,ESTABLISHED -j ACCEPT
      ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
      ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
      ip6tables-save > /etc/iptables/rules.v6
    } || {
      print_status message error \
        "Something went wrong, attempting to restore backup..."
      restore_firewall || print_status message error "Backup restoration failed"
      return 1
    }
    systemctl enable --now netfilter-persistent
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
  if [[ " ${FIREWALLS[*]} " =~ " firewalld " \
    && "$DISTRO" =~ ^(centos|rocky|almalinux|fedora|rhel|ol|sles|opensuse*|suse)$ ]]; then
    active_firewall="firewalld"
  elif [[ " ${FIREWALLS[*]} " =~ " ufw " \
    && "$DISTRO" =~ ^(ubuntu|debian)$ ]]; then
    active_firewall="ufw"
  elif [[ " ${FIREWALLS[*]} " =~ " nftables " ]]; then
    active_firewall="nftables"
  elif [[ " ${FIREWALLS[*]} " =~ " iptables " ]]; then
    active_firewall="iptables"
  else
    print_status message error "Unrecognized firewall"
    return 1
  fi

  local ip_blocking="disabled"
  local -a rulelist=()

  # rulelist of possible outbound ports, with a default value of ALLOW or DROP next to it
  local -A outbound_rulelist=(
    ["http:80/tcp"]="ALLOW"
    ["https:443/tcp"]="ALLOW"
    ["dns:53/udp"]="ALLOW"
    ["dns-xfr:53/tcp"]="DROP"
    ["dhcp-client:68/udp"]="ALLOW"
    ["ntp:123/udp"]="ALLOW"
    ["wazuh-agent:1514/tcp"]="ALLOW"
    ["wazuh-enroll:1515/tcp"]="ALLOW"
    ["wazuh-api:55000/tcp"]="ALLOW"
    ["splunk-agent:9997/tcp"]="DROP"
  )
  # workaround to print out outbound_rulelist in a given order
  local -ar outbound_rulelist_order=(
    "http:80/tcp"
    "https:443/tcp"
    "dns:53/udp"
    "dns-xfr:53/tcp"
    "dhcp-client:68/udp"
    "ntp:123/udp"
    "wazuh-agent:1514/tcp"
    "wazuh-enroll:1515/tcp"
    "wazuh-api:55000/tcp"
    "splunk-agent:9997/tcp"
  )
  local -ar service_ports=(
    ftp-data:20/tcp
    ftp:21/tcp
    ssh:22/tcp
    telnet:23/tcp
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
    wazuh-agent:1514/tcp
    wazuh-enroll:1515/tcp
    mysql:3306/tcp
    rdp:3389/tcp
    rdp-udp:3389/udp
    vnc:5900/tcp
    splunk:8089/tcp
    wazuh-indexer:9200/tcp
    splunk-agent:9997/tcp
    wazuh-api:55000/tcp
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
          print_status already_exists error rule "$rule" rude
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
        printf "Added rule %b%s%b to rulelist\n" "${YELLOW}" "${append}" "${NC}"
      else
        print_status invalid_input error "try again"
      fi
      service="" protocol="" valid_port="false" valid_name="false" append=""
    done
  }

  fw_delete_rules() {
    local service="" protocol="" port_prot="" valid_input="false" rule=""
    local -a temp_rulelist=()
    while true; do
      if [[ "${#rulelist[@]}" -le 0 ]]; then
        print_status message info "Rulelist is empty"
        return 0
      fi
      fw_show_inbound
      read -rp "Enter port & protocol to delete (q to exit): " service protocol
      if [[ "$service" = "q" ]]; then
        return 0
      fi
      # For verifying that given input is valid
      # Is input only numbers, then is it a valid port number, and finally
      # did they specify a valid protocol?
      if [[ "$service" =~ ^[0-9]+$ ]]; then
        if ((service >= 1 && service <= 65535)); then
          if [[ "$protocol" =~ ^(tcp|udp)$ ]]; then
            valid_input="true"
            port_prot="${service}/${protocol}"
          fi
        fi
      fi
      if [[ "$valid_input" == "true" ]]; then
        for rule in "${rulelist[@]}"; do
          [[ "$rule" == "$port_prot" ]] || temp_rulelist+=("$rule")
        done
        rulelist=("${temp_rulelist[@]}")
        temp_rulelist=()
        service="" protocol="" port_prot="" valid_input="false" rule=""
        continue
      fi
      print_status invalid_input error "try again"
      temp_rulelist=()
      service="" protocol="" port_prot="" valid_input="false" rule=""
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
      printf "%bip%b to toggle IP blocking\n" "${YELLOW}${BOLD}" "$NC"
      read -rp "Enter service name to toggle (q to exit): " reply
      case "$reply" in
        q)
          return 0
          ;;
        ip)
          if [[ "$ip_blocking" == "disabled" ]]; then
            ip_blocking="enabled"
          else
            ip_blocking="disabled"
          fi
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

  fw_show_inbound() {
    local rule=""
    if [[ "${#rulelist[@]}" -le 0 ]]; then
      print_status message info "Rulelist is empty"
      return 0
    fi
    for rule in "${rulelist[@]}"; do
      printf "%b%s%b " "$YELLOW" "$rule" "$NC"
    done
    printf "\n"
  }

  fw_show_outbound() {
    for outbound_service in "${outbound_rulelist_order[@]}"; do
      if [[ "${outbound_rulelist[$outbound_service]}" == "ALLOW" ]]; then
        printf "%-25s : %b%7s%b\n" \
          "$outbound_service" "${GREEN}${BOLD}" "ALLOW" "$NC"
      else
        printf "%-25s : %b%7s%b\n" \
          "$outbound_service" "${RED}${BOLD}" "DROP" "$NC"
      fi
    done
    printf "%bALLOW%b only specific IPs: " "${GREEN}${BOLD}" "$NC"
    if [[ $ip_blocking == "enabled" ]]; then
      printf "%b%s%b\n" "${GREEN}${BOLD}" "ENABLED" "$NC"
    else
      printf "%b%s%b\n" "${RED}${BOLD}" "DISABLED" "$NC"
    fi
  }

  fw_list_services() {
    local service=""
    for service in "${service_ports[@]}"; do
      printf "%b%s%b " "$YELLOW" "$service" "$NC"
    done
    printf "\n"
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
    printf "Please confirm this information is correct:\n"
    printf "%bFirewall:%b %b%s%b\n" \
      "$YELLOW" "$NC" "$RED" "$active_firewall" "$NC"
    printf "%bInbound Allowed ports:\n" "$YELLOW"
    fw_show_inbound
    printf "%bOutbound Allowed ports:%b\n" "$YELLOW" "$NC"
    fw_show_outbound
    if [[ "$active_firewall" = "firewalld" ]]; then
      local interface=""
      local interfaces
      mapfile -t interfaces < <(ip -o link show | awk -F': ' '{print $2}' \
        | grep -vE '^(lo|docker.*|br-.*|podman.*|tun.*|tap.*|wg.*|veth.*|tailscale.*)$')
      printf "%bInterfaces:\n" "$YELLOW"
      for interface in "${interfaces[@]}"; do
        printf "${YELLOW}%s ${NC}" "$interface"
      done
      printf "\n"
      interface=""
    fi
    printf "%bIs this information correct?%b\n" "$RED" "$NC"
    while true; do
      read -rp "(y/n): " reply
      case $reply in
        y) 
          reply=""
          break
          ;;
        n)
          jclr
          return 0
          ;;
        *)
          print_status unrecognized_option error "$reply" kind
          reply=""
          ;;
      esac
    done

    jclr
    printf "%b[FINAL WARNING]%b\n" "${RED}${BOLD}" "$NC"
    printf \
      "%bThis will overwrite your real, permanent firewall configuration%b\n" \
      "${RED}${BOLD}" "$NC"
    printf \
      "%bDefault policy will become drop for input and output%b\n" \
      "${RED}${BOLD}" "$NC"
    printf "Please double check to confirm this information is correct:\n"
    printf "%bFirewall:%b %b%s%b\n" \
      "$YELLOW" "$NC" "$RED" "$active_firewall" "$NC"
    printf "%bInbound Allowed ports:\n" "$YELLOW"
    fw_show_inbound
    printf "%bOutbound Allowed ports:%b\n" "$YELLOW" "$NC"
    fw_show_outbound
    if [[ "$active_firewall" = "firewalld" ]]; then
      printf "%bInterfaces:\n" "$YELLOW"
      for interface in "${interfaces[@]}"; do
        printf "${YELLOW}%s ${NC}" "$interface"
      done
    printf "\n"
    fi
    printf "%bOnce more: is this information correct?%b\n" "${RED}${BOLD}" "$NC"
    while true; do
      read -rp "(y/n): " reply
      case $reply in
        y)
          reply=""
          break
          ;;
        n)
          jclr
          return 0
          ;;
        *) 
          print_status unrecognized_option error "$reply" kind
          reply=""
          ;;
      esac
    done
    local rule
    local port
    local protocol
    local port_prot
    jclr
    print_status message_object info firewall \
      "Applying rules to" "$active_firewall"
    print_status message warn "Specific IP blocking for outbound ports is not yet available"
    # There is no default drop policy for output packets on firewalld,
    # therefore rich rules have to be used
    if [[ "$active_firewall" = "firewalld" ]]; then
      {
        print_status message info "Backing up configuration..."
        backup_firewall firewalld finalize
        firewall-cmd --new-zone=hardened --permanent
        firewall-cmd --zone=hardened --set-target=DROP --permanent
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv4 direction="out" drop'
        firewall-cmd --zone=hardened --permanent \
          --add-rich-rule='rule family=ipv6 direction="out" drop'
        for outbound_service in "${!outbound_rulelist[@]}"; do
          port_prot=$(echo "$outbound_service" | cut -d ":" -f 2)
          port=$(echo "$port_prot" | cut -d "/" -f 1)
          protocol=$(echo "$port_prot" | cut -d "/" -f 2)
          if [[ "${outbound_rulelist[$outbound_service]}" == "ALLOW" ]]; then
            firewall-cmd --zone=hardened --permanent \
              --add-rich-rule="rule family=ipv4 direction='out' port port='$port' protocol='$protocol' accept"
            firewall-cmd --zone=hardened --permanent \
              --add-rich-rule="rule family=ipv6 direction='out' port port='$port' protocol='$protocol' accept"
          fi
        done
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
        print_status message info "Backing up configuration..."
        backup_firewall ufw finalize
        for rule in "${rulelist[@]}"; do
          port=$(echo "$rule" | cut -d "/" -f 1)
          protocol=$(echo "$rule" | cut -d "/" -f 2)
          ufw allow in "${port}/${protocol}"
        done
        for outbound_service in "${!outbound_rulelist[@]}"; do
          port_prot=$(echo "$outbound_service" | cut -d ":" -f 2)
          if [[ "${outbound_rulelist[$outbound_service]}" == "ALLOW" ]]; then
            ufw allow out "$port_prot"
          fi
        done
        ufw default deny incoming
        ufw default deny outgoing
      } || {
        print_status message error \
          "Something went wrong, attempting to restore backup..."
        restore_firewall || print_status message error "Backup restoration failed"
        return 1
      }

    elif [[ "$active_firewall" = "nftables" ]]; then
      if ! nft list table inet filter &>/dev/null; then
        printf "${RED}%s${YELLOW}%s${NC}" \
          "table inet filter Not Found, please ensure you ran" "fwinit"
        return 1
      fi
      if ! nft list chain inet filter INPUT &>/dev/null \
        && ! nft list chain inet filter OUTPUT &>/dev/null \
        && ! nft list chain inet filter FORWARD &>/dev/null; then
        printf "${RED}%s${YELLOW}%s${NC}" \
          "Chain for INPUT, OUTPUT, or FORWARD was not found. Please ensure you ran" \
          "fwinit"
        return 1
      fi
      {
        print_status message info "Backing up configuration..."
        backup_firewall nftables finalize
        for rule in "${rulelist[@]}"; do
          port=$(echo "$rule" | cut -d "/" -f 1)
          protocol=$(echo "$rule" | cut -d "/" -f 2)
          nft add rule inet filter INPUT "$protocol" dport "$port" accept
        done
        for outbound_service in "${!outbound_rulelist[@]}"; do
          port_prot=$(echo "$outbound_service" | cut -d ":" -f 2)
          port=$(echo "$port_prot" | cut -d "/" -f 1)
          protocol=$(echo "$port_prot" | cut -d "/" -f 2)
          if [[ "${outbound_rulelist[$outbound_service]}" == "ALLOW" ]]; then
            nft add rule inet filter OUTPUT "$protocol" dport "$port" accept
          fi
        done
        nft chain inet filter INPUT '{ policy drop; }'
        nft chain inet filter OUTPUT '{ policy drop; }'
        if [[ "$DISTRO" =~ ^(centos|rocky|almalinux|fedora|rhel|ol|sles|opensuse.*|suse)$ ]]; then
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
        print_status message info "Backing up configuration..."
        backup_firewall iptables finalize
        for rule in "${rulelist[@]}"; do
          port=$(echo "$rule" | cut -d "/" -f 1)
          protocol=$(echo "$rule" | cut -d "/" -f 2)
          iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT
          ip6tables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT
        done
        for outbound_service in "${!outbound_rulelist[@]}"; do
          port_prot=$(echo "$outbound_service" | cut -d ":" -f 2)
          port=$(echo "$port_prot" | cut -d "/" -f 1)
          protocol=$(echo "$port_prot" | cut -d "/" -f 2)
          if [[ "${outbound_rulelist[$outbound_service]}" == "ALLOW" ]]; then
            iptables -A OUTPUT -p "$protocol" --dport "$port" -j ACCEPT
            ip6tables -A OUTPUT -p "$protocol" --dport "$port" -j ACCEPT
          fi
        done
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
    print_status message success "Firewall configured"
  }

  fw_help() {
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "a | append" "Allows you to append allow inbound rules to rulelist"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "t | toggle" "Allows you to toggle allow outbound rules on rulelist"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "d | delete" "Will let you delete a specific inbound rule on rulelist"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "r | reset" "Will delete all of your rules on rulelist"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "s | show" "Will show your rulelist"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "l | list" "Will list available service names"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "f | finalize" "Will implement your rulelist onto the permanent firewall configuration"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "h | help" "Will show you this prompt again"
    printf "${YELLOW}${BOLD}%-15s${NC} :\t %s\n" "q | quit" "Will quit to main menu, without saving any changes"
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
  jclr
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
        fw_list_services
        ;;
      show | s)
        printf "Inbound Allow Rules:\n"
        fw_show_inbound
        printf "Outbound Rules:\n"
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
      print_status message success "Backup completed"
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
      print_status message success "Backup completed"
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
      print_status message success "Backup completed"
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
      print_status message success "Backup completed"
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
  print_status message success "Backups restored"
}
