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
# TODO: 3.1.1 should be left up to user through sysctl (ipv6 necessary or not?)
# TODO: 7.1.13 could likely be implemented via linpeas.sh

# TODO: net.ipv6.conf.all.disable_ipv6 = 0
# Optionally disable ipv6 on the system.

# TODO: (5.4.2)

# TODO: (5.4.3.1, 5.4.3.2-3(?))

# TODO: (6.1.1, 6.1.4), (6.1.2-3 (maybe))

# TODO: auditd autoconfig (6.2), including adding .rules files to /etc/audit/rules.d/ (specified in 6.2.3)

# TODO: aide autoconfig (6.3)

# TODO: Supplementary security tools autoconfig (fail2ban, ossec, clamav, chkrootkit, lynis)

# I will add set -euo pipefail to this script, once it becomes important to make it stable and not possibly obliterate your system
set -u

# Set ANSI Escape Code variables for different colors in the terminal
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[0;33m'
declare -r BLUE='\033[0;34m'
declare -r MAGENTA='\033[0;35m'
declare -r CYAN='\033[0;36m'
declare -r NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${BLUE}This script must be run as ${RED}root${BLUE}, or with sudo.${NC}" >&2
    exit 1
fi

# Sets up variables, and checks for important system information
init() {
    # Determine distro being used
    if [ -f /etc/os-release ]; then
        # freedesktop.org and systemd
        . /etc/os-release
        DISTRO=$ID
        VER=$VERSION_ID
    elif type lsb_release &> /dev/null; then
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
    echo -e "${GREEN}Distribution ID:${NC} $DISTRO $VER"

    # Choose correct package manager for distro
    case "$DISTRO" in
        ubuntu|debian|linuxmint)
            if command -v apt &> /dev/null; then
                PKG_MANAGER="apt"
            else
                PKG_MANAGER="dpkg"
            fi
            ;;
        centos|rocky|almalinux|fedora|rhel|ol)
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
            elif command -v yum &> /dev/null; then
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

    echo -e "${GREEN}Packge Manager:${NC} $PKG_MANAGER"

    # Find firewalls installed on the system
    # This should be modified to use an indexed array rather than appending to a string
    FIREWALLS=""

    # firewalld
    if command -v firewall-cmd &> /dev/null; then
        FIREWALLS+="firewalld "
    fi

    # ufw
    if command -v ufw &> /dev/null; then
        FIREWALLS+="ufw "
    fi

    # nftables
    if command -v nft &> /dev/null; then
        FIREWALLS+="nftables "
    fi

    # iptables
    if command -v iptables &> /dev/null; then
        FIREWALLS+="iptables "
    fi

    # Trim trailing space
    FIREWALLS="${FIREWALLS%" "}"

    echo -e "${GREEN}Installed Firewalls:${NC} ${RED}$FIREWALLS${NC}"
}

install_package() {
    local package_manager="$1"
    if [[ -z "$package_manager" ]]; then
        echo "Error: No package manager provided to install_package."
        return 1
    fi

    local package_name="$2"
    if [[ -z "$package_name" ]]; then
        echo "Error: No package name provided to install_package."
        return 1
    fi

    if [[ "$package_manager" == "unsupported" ]]; then
        echo "Error: Unsupported operating system."
        return 1
    fi

    case "$package_manager" in
        apt)
            echo "Using apt to install $package_name..."
            apt install -y "$package_name"
            ;;
        dnf)
            echo "Using dnf to install $package_name..."
            dnf install -y "$package_name"
            ;;
        yum)
            echo "Using yum to install $package_name..."
            yum install -y "$package_name"
            ;;
        zypper)
            echo "Using zypper to install $package_name..."
            zypper install -y "$package_name"
            ;;
        pacman)
            echo "Using pacman to install $package_name..."
            pacman -Syu --noconfirm "$package_name"
            ;;
        *)
            echo "Error: Unsupported package manager."
            return 1
            ;;
    esac
}

remove_package() {
    local package_manager="$1"
    if [[ -z "$package_manager" ]]; then
        echo "Error: No package manager provided to remove_package."
        return 1
    fi

    local package_name="$2"
    if [[ -z "$package_name" ]]; then
        echo "Error: No package name provided to remove_package."
        return 1
    fi

    if [[ "$package_manager" == "unsupported" ]]; then
        echo "Error: Unsupported operating system."
        return 1
    fi

    case "$package_manager" in
        apt)
            echo "Using apt to remove $package_name..."
            apt remove "$package_name"
            ;;
        dnf)
            echo "Using dnf to remove $package_name..."
            dnf remove "$package_name"
            ;;
        yum)
            echo "Using yum to remove $package_name..."
            yum remove "$package_name"
            ;;
        zypper)
            echo "Using zypper to remove $package_name..."
            zypper remove "$package_name"
            ;;
        pacman)
            echo "Using pacman to remove $package_name..."
            pacman -R "$package_name"
            ;;
        *)
            echo "Error: Unsupported package manager."
            return 1
            ;;
    esac
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
        ubuntu|debian|linuxmint)
            local -ar candidate_pkgs=(
                autofs avahi-daemon isc-dhcp-server bind9 dnsmasq vsftpd slapd dovecot-imapd nfs-kernel-server ypserv cups rpcbind
                rsync samba snmpd tftpd-hpa squid apache2 nginx xinetd xserver-common nis rsh-client talk telnet inetutils-telnet
                ldap-utils ftp tnftp netcat-openbsd netcat-traditional ncat wireshark tshark tcpdump gcc make rsh-server telnetd nmap proftpd
                pure-ftpd inetutils-inetd openbsd-inetd rinetd rlinetd unbound lighttpd
            )
            for pkg in "${candidate_pkgs[@]}"; do
                dpkg-query -s "$pkg" &>/dev/null && PACKAGES+=("$pkg")
            done
            ;;
        centos|rocky|almalinux|fedora|rhel|ol)
            local -ar candidate_pkgs=(
                mcstrans setroubleshoot autofs avahi dhcp-server bind dnsmasq samba vsftpd dovecot cyrus-imapd nfs-utils ypserv cups rpcbind rsync-daemon
                net-snmp telnet-server tftp-server squid httpd nginx xinetd xorg-x11-server-common ftp openldap-clients ypbind telnet tftp 
                netcat nmap-ncat wireshark wireshark-cli tcpdump gcc make rsh rsh-server nmap proftpd pure-ftpd unbound lighttpd
            )
            for pkg in "${candidate_pkgs[@]}"; do
                rpm -q "$pkg" &>/dev/null && PACKAGES+=("$pkg")
            done
            ;;
        *)
            echo "You must manually check, sorry."
            ;;
    esac
    echo -e "${YELLOW}The following packages of concern were found:${NC}"
    for pkg in "${PACKAGES[@]}"; do
        echo -e "${RED}$pkg${NC}"
    done
}

ask_to_remove_packages() {
    echo "Not yet implemented."
    return 1
}

install_recommended_packages() {
    local remote_logging="false"
    local extra_security="false"
    local arg=""
    local pkg=""

    for arg in "$@"; do
        case "$arg" in
            remote_logging=true) remote_logging="true" ;;
            remote_logging=false) remote_logging="false" ;;
            extra_security=true) extra_security="true" ;;
            extra_security=false) extra_security="false" ;;
            *) echo "Unrecognized argument: $arg" >&2; return 1 ;;
        esac
    done

    case "$DISTRO" in
        ubuntu|debian)
            if [ "$remote_logging" = "true" ]; then
                for pkg in "rsyslog" "systemd-journal-remote"; do
                    install_package "$PKG_MANAGER" "$pkg"
                done
            fi
            if [ "$extra_security" = "true" ]; then
                for pkg in "lynis" "clamav" "chkrootkit" "fail2ban"; do
                    install_package "$PKG_MANAGER" "$pkg"
                done
            fi
            for pkg in "sudo" "apparmor" "auditd" "aide"; do
                install_package "$PKG_MANAGER" "$pkg"
            done
            ;;
        centos|rocky|almalinux|fedora|rhel|ol)
            if [ "$remote_logging" = "true" ]; then
                for pkg in "rsyslog" "systemd-journal-remote"; do
                    install_package "$PKG_MANAGER" "$pkg"
                done
            fi
            if [ "$extra_security" = "true" ]; then
                for pkg in "lynis" "clamav" "chkrootkit" "fail2ban"; do
                    install_package "$PKG_MANAGER" "$pkg"
                done
            fi
            for pkg in "sudo" "libselinux" "audit" "aide"; do
                install_package "$PKG_MANAGER" "$pkg"
            done
            ;;
        *)
            echo "Unrecognized package manager"
            return 1
            ;;
    esac
}

# Basic tar backup function for /etc, /var/www/html, and /opt to directory specified in env ($BAKDIR), defaults to /usr/sbin/ if unspecified
# Will also try to make deleting or modifying backups a little annoying
# Will put your backups into the child directory <backup_directory>/b4
backup_directories() {
    local backup_directory="${BAKDIR:-/usr/sbin}"
    if [ ! -d "$backup_directory" ]; then
        echo -e "${RED}Backup directory does not exist${NC}"
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
            chattr +"$flag" "$etc_backup" &> /dev/null || true
        done
    fi
    if [ -d "/var/www/html" ]; then
        echo -e "Backing up ${YELLOW}/var/www/html${NC}"
        local html_backup=""
        html_backup="${backup_path}/httml-$(date +%b-%d-%H.%M.%S)"
        tar -cf "$html_backup" /var/www/html &> /dev/null || true
        for flag in u a i; do
            chattr +"$flag" "$html_backup" &> /dev/null || true
        done
    fi
    if [ -d "/opt" ]; then
        echo -e "Backing up ${YELLOW}/opt${NC}"
        local opt_backup=""
        opt_backup="${backup_path}/oppt-$(date +%b-%d-%H.%M.%S)"
        tar -cf "$opt_backup" /opt &> /dev/null || true
        for flag in u a i; do
            chattr +"$flag" "$opt_backup" &> /dev/null || true
        done
    fi
    echo -e "Done. You can find your backups at ${YELLOW}${backup_path}${NC}"
}

# CIS Debian 12: 1.4.2, 1.6.4-6, 2.4.1.2-7, 2.4.1.8 (partially), 7.1.1-10, 5.1.1
configure_permissions() {
    # 1.4.2
    if [ -f /etc/grub/grub.cfg ]; then
        chown root:root /boot/grub/grub.cfg && chmod 0600 /boot/grub/grub.cfg
    else
        echo -e "${CYAN}File ${YELLOW}/boot/grub/grub.cfg${RED} Does not exist.${NC}"
    fi

    # 1.6.4-6
    if [ -f /etc/motd ]; then
        chown root:root /etc/motd && chmod 644 /etc/motd
    else
        echo -e "${CYAN}File ${YELLOW}/etc/motd${RED} Does not exist.${NC}"
    fi
    if [ -f /etc/issue ]; then
        chown root:root /etc/issue && chmod 644 /etc/issue
    else
        echo -e "${CYAN}File ${YELLOW}/etc/issue${RED} Does not exist.${NC}"
    fi
    if [ -f /etc/issue.net ]; then
        chown root:root /etc/issue.net && chmod 644 /etc/issue.net
    else
        echo -e "${CYAN}File ${YELLOW}/etc/issue${RED} Does not exist.${NC}"
    fi

    # 2.4.1.2-7
    if [ -f /etc/crontab ]; then 
        chown root:root /etc/crontab && chmod 600 /etc/crontab
    else
        echo -e "${CYAN}File ${YELLOW}/etc/crontab${RED} Does not exist.${NC}"
    fi
    if [ -d /etc/cron.hourly ]; then
        chown root:root /etc/cron.hourly && chmod 700 /etc/cron.hourly
    else
        echo -e "${MAGENTA}Directory ${YELLOW}/etc/cron.hourly${RED} Does not exist.${NC}"
    fi
    if [ -d /etc/cron.daily ]; then
        chown root:root /etc/cron.daily && chmod 700 /etc/cron.daily
    else
        echo -e "${MAGENTA}Directory ${YELLOW}/etc/cron.hourly${RED} Does not exist.${NC}"
    fi
    if [ -d /etc/cron.weekly ]; then
        chown root:root /etc/cron.weekly && chmod 700 /etc/cron.weekly
    else
        echo -e "${MAGENTA}Directory ${YELLOW}/etc/cron.hourly${RED} Does not exist.${NC}"
    fi
    if [ -d /etc/cron.monthly ]; then
        chown root:root /etc/cron.monthly && chmod 700 /etc/cron.monthly
    else
        echo -e "${MAGENTA}Directory ${YELLOW}/etc/cron.hourly${RED} Does not exist.${NC}"
    fi
    if [ -d /etc/cron.d ]; then
        chown root:root /etc/cron.d && chmod 700 /etc/cron.d
    else
        echo -e "${MAGENTA}Directory ${YELLOW}/etc/cron.d${RED} Does not exist.${NC}"
    fi

    # 2.4.1.8 (partially) (possible issues on systems with crontab group)
    #[ -f /etc/cron.allow] && chown root:root /etc/cron.allow && chmod 640 /etc/cron.allow
    #[ -f /etc/cron.deny] && chown root:root /etc/cron.deny && chmod 640 /etc/cron.deny

    # 7.1.1-10
    if [ -f /etc/passwd ]; then
        chown root:root /etc/passwd && chmod 644 /etc/passwd
    else
        echo -e "${CYAN}File ${YELLOW}/etc/passwd${RED} Does not exist.${NC}"
    fi
    if [ -f /etc/passwd- ]; then
        chown root:root /etc/passwd- && chmod 644 /etc/passwd-
    else
        echo -e "${CYAN}File ${YELLOW}/etc/passwd-${RED} Does not exist.${NC}"
    fi
    if [ -f /etc/group ]; then
        chown root:root /etc/group && chmod 644 /etc/group
    else
        echo -e "${CYAN}File ${YELLOW}/etc/group${RED} Does not exist.${NC}"
    fi
    if [ -f /etc/group- ]; then
        chown root:root /etc/group- && chmod 644 /etc/group-
    else
        echo -e "${CYAN}File ${YELLOW}/etc/group-${RED} Does not exist.${NC}"
    fi
    case "$DISTRO" in
        debian|ubuntu)
            if [ -f /etc/shadow ]; then
                chown root:shadow /etc/shadow && chmod 640 /etc/shadow
            else
                echo -e "${CYAN}File ${YELLOW}/etc/shadow${RED} Does not exist.${NC}"
            fi
            if [ -f /etc/shadow- ]; then
                chown root:shadow /etc/shadow- && chmod 640 /etc/shadow-
            else
                echo -e "${CYAN}File ${YELLOW}/etc/shadow-${RED} Does not exist.${NC}"
            fi
            if [ -f /etc/gshadow ]; then
                chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow
            else
                echo -e "${CYAN}File ${YELLOW}/etc/gshadow${RED} Does not exist.${NC}"
            fi
            if [ -f /etc/gshadow- ]; then
                chown root:shadow /etc/gshadow- && chmod 640 /etc/gshadow-
            else
                echo -e "${CYAN}File ${YELLOW}/etc/gshadow-${RED} Does not exist.${NC}"
            fi
            ;;
        centos|rocky|almalinux|fedora|rhel|ol|opensuse*)
            if [ -f /etc/shadow ]; then
                chown root:root /etc/shadow && chmod 000 /etc/shadow
            else
                echo -e "${CYAN}File ${YELLOW}/etc/shadow${RED} Does not exist.${NC}"
            fi
            if [ -f /etc/shadow- ]; then
                chown root:root /etc/shadow- && chmod 000 /etc/shadow-
            else
                echo -e "${CYAN}File ${YELLOW}/etc/shadow-${RED} Does not exist.${NC}"
            fi
            if [ -f /etc/gshadow ]; then
                chown root:root /etc/gshadow && chmod 000 /etc/gshadow
            else
                echo -e "${CYAN}File ${YELLOW}/etc/gshadow${RED} Does not exist.${NC}"
            fi
            if [ -f /etc/gshadow- ]; then
                chown root:root /etc/gshadow- && chmod 000 /etc/gshadow-
            else
                echo -e "${CYAN}File ${YELLOW}/etc/gshadow-${RED} Does not exist.${NC}"
            fi
            ;;
        *)
            echo "You should configure /etc/shadow and /etc/gshadow yourself."
            ;;
    esac
    if [ -f /etc/shells ]; then
        chown root:root /etc/shells && chmod 644 /etc/shells
    else
        echo -e "${CYAN}File ${YELLOW}/etc/shells${RED} Does not exist.${NC}"
    fi
    if [ -f /etc/security/opasswd ]; then
        chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd
    else
        echo -e "${CYAN}File ${YELLOW}/etc/security/opasswd${RED} Does not exist.${NC}"
    fi
    if [ -f /etc/security/opasswd.old ]; then
        chown root:root /etc/security/opasswd.old && chmod 600 /etc/security/opasswd.old
    else
        echo -e "${CYAN}File ${YELLOW}/etc/security/opasswd.old${RED} Does not exist.${NC}"
    fi

    # 5.1.1
    if [ -f /etc/ssh/sshd_config ]; then
        chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config
    else
        echo -e "${CYAN}File ${YELLOW}/etc/security/sshd_config${RED} Does not exist.${NC}"
    fi
    if [ -d /etc/ssh/sshd_config.d ]; then
        for file in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$file" ] || continue
            chown root:root "$file"
            chmod 600 "$file"
        done
    fi
}

# CIS Debian 12: 1.1.1.1-5,8-9, 3.2
# MANUAL: 1.1.1.10
# Will disable unnecessary kernel modules
disable_kernel_modules() {
    modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage" "dccp" "tipc" "rds" "sctp")
    local custom_blacklist="/etc/modprobe.d/custom-blacklist.conf"
    local mod=""
    touch "$custom_blacklist"

    # Check for duplicates entries, then add an entry if it doesn't exist.
    for mod in "${modules[@]}"; do
        if ! grep -qE "^install[[:space:]]+${mod}[[:space:]]+" "$custom_blacklist"; then
            echo "install $mod /bin/false" >> "$custom_blacklist"
        fi
    done
}

# Configure sysctl parameters to harden the system
configure_sysctl() {
    local sysctl_file="/etc/sysctl.d/99-hardening.conf"
    local limits_file="/etc/security/limits.d/99-disable-dump.conf"

    declare -A settings=(
        ["kernel\.randomize_va_space"]="2"
        ["kernel\.yama\.ptrace_scope"]="2"
        ["fs\.suid_dumpable"]="0"
        ["net\.ipv4\.icmp_ignore_bogus_error_responses"]="1"
        ["net\.ipv4\.icmp_echo_ignore_broadcasts"]="1"
        ["net\.ipv4\.conf\.all\.rp_filter"]="2"
        ["net\.ipv4\.conf\.default\.rp_filter"]="2"
        ["net\.ipv4\.conf\.all\.log_martians"]="1"
        ["net\.ipv4\.conf\.default\.log_martians"]="1"
        ["net\.ipv4\.tcp_syncookies"]="1"
    )

    touch "$sysctl_file"
    touch "$limits_file"

    # Here is a simplified explanation of this terrifying code:
    # We iterate through each KEY in the associative array called settings (!settings[@])
    # The settings array has multiple escape characters for periods, so grep doesn't interpret them as a metacharacter
    # We then fetch the VALUE for that specific key (settings[$key])
    # If we can find the line which has the relevant key, we edit it with sed to change to the correct value
    # Otherwise, we append a new line with the correct key=value pair
    # We also use sysctl -w to immediately apply the change
    # (this may be complete overkill)
    for key in "${!settings[@]}"; do
        local value="${settings[$key]}"
        if grep -q -E "^${key}\s*=" "$sysctl_file"; then
            sed -i "s|^${key}\s*=.*|${key} = ${value}|" "$sysctl_file"
        else
            echo "${key} = ${value}" >> "$sysctl_file"
        fi

        sysctl -w "${key}=${value}" &> /dev/null
    done

    # Disable core dumps
    if [ ! -d "/etc/security/limits.d" ]; then
        mkdir -p /etc/security/limits.d
    fi
    echo "* hard core 0" > "$limits_file"

}

# Will present the main menu
main() { 
    init
    source "$HOME/.env" &> /dev/null || echo -e "${YELLOW}Couldn't find .env file${NC}"
    check_installed_packages
}

main