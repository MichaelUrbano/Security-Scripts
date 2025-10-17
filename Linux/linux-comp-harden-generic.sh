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

# TODO: aide autoconfig (6.3)

# TODO: Supplementary security tools autoconfig (fail2ban, ossec, clamav, chkrootkit, lynis)

# I will add set -euo pipefail to this script, once it becomes important to make it stable and not possibly obliterate your system
set -uo pipefail

# Set ANSI Escape Code variables for different colors in the terminal, as well as recommended, but not strict, usage of colors.
readonly RED='\033[0;31m' # For Warnings
readonly GREEN='\033[0;32m' # For "All Clear"
readonly YELLOW='\033[0;33m' # For Commands or Options
readonly BLUE='\033[0;34m' # For Info
readonly MAGENTA='\033[0;35m' # For Directories
readonly CYAN='\033[0;36m' # For Files
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${BLUE}This script must be run as ${RED}root${BLUE}, or with sudo.${NC}" >&2
    exit 1
fi

# Set to "true" if you want to ignore the main menu, possibly to run functions directly
SKIP_MAIN="false"

# Sets up global variables, and checks for important system information
init() {
    # Determine distro being used
    if [ -f /etc/os-release ]; then
        # freedesktop.org
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
    FIREWALLS=()
    local firewall=""

    # firewalld
    if command -v firewall-cmd &> /dev/null; then
        FIREWALLS+=("firewalld")
    fi

    # ufw
    if command -v ufw &> /dev/null; then
        FIREWALLS+=("ufw")
    fi

    # nftables
    if command -v nft &> /dev/null; then
        FIREWALLS+=("nftables")
    fi

    # iptables
    if command -v iptables &> /dev/null; then
        FIREWALLS+=("iptables")
    fi

    echo -ne "${GREEN}Installed Firewalls: ${NC}"
    for firewall in "${FIREWALLS[@]}"; do
        echo -ne "${RED}${firewall}${NC} "
    done
    echo ""

    # Check if commands are present, and if their services are enabled
    # One of these should be added for aide
    case "$DISTRO" in
        ubuntu|debian|linuxmint)
            if systemctl is-active --quiet apparmor; then
                echo -e "${YELLOW}apparmor.service ${NC}: ${GREEN}running${NC}"
                if command -v aa-status &> /dev/null; then
                    echo -e "${YELLOW}apparmor-utils ${NC}: ${GREEN}installed${NC}"
                else
                    echo -e "${YELLOW}apparmor-utils ${NC}: ${RED}missing${NC}"
                fi
            else
                echo -e "${YELLOW}apparmor.service ${NC}: ${RED}not running${NC}"
            fi
            ;;
        centos|rocky|almalinux|fedora|rhel|ol|opensuse*)
            if [[ ! -e /sys/fs/selinux/enforce ]]; then
                echo -e "${YELLOW}SELinux ${NC}: ${RED}not enabled${NC}"
            elif [[ $(cat /sys/fs/selinux/enforce) -eq 1 ]]; then
                echo -e "${YELLOW}SELinux ${NC}: ${GREEN}enforcing${NC}"
            else
                echo -e "${YELLOW}SELinux ${NC}: ${RED}not enforcing${NC}"
            fi
            ;;
    esac

    if systemctl is-active --quiet auditd; then
        echo -e "${YELLOW}auditd.service ${NC}: ${GREEN}running${NC}"
    else
        echo -e "${YELLOW}auditd.service ${NC}: ${RED}not running${NC}"
    fi

    if systemctl is-active --quiet dailyaidecheck.timer; then
        echo -e "${YELLOW}dailyaidecheck.timer ${NC}: ${GREEN}running${NC}"
    else
        echo -e "${YELLOW}dailyaidecheck.timer ${NC}: ${RED}not running${NC}"
    fi

    command -v sudo &> /dev/null || echo -e "${RED}WARNING: ${YELLOW}sudo ${RED}IS NOT INSTALLED${NC}"

    # Check for duplicate UIDs/GIDs and users/groups, as well as users with passwords
    # CIS Ubuntu 5.4.2 and 7.2
    mapfile -t DUPLICATE_UIDS < <(
        awk -F: '{ print $3 }' /etc/passwd | sort | uniq -d
    )
    mapfile -t DUPLICATE_PRIMARY_GIDS < <(
        awk -F: '{ print $4 }' /etc/passwd | sort | uniq -d
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
        echo -e "${YELLOW}Duplicate UIDs found${NC}"
        local uid=""
        for uid in "${DUPLICATE_UIDS[@]}"; do
            if [[ "$uid" -eq 0 ]]; then
                echo -e "${RED}WARNING: Duplicate UID 0 account found${NC}"
            fi
                awk -F: -v uid="$uid" '($3 == uid) { print "User:", $1, "| UID:", $3 }' /etc/passwd
        done
    fi
    if [[ "${#DUPLICATE_PRIMARY_GIDS[@]}" -gt 0 ]]; then
        echo -e "${YELLOW}Some users share the same primary GID${NC}"
        local pgid=""
        for pgid in "${DUPLICATE_PRIMARY_GIDS[@]}"; do
            if [[ "$pgid" -eq 0 ]]; then
                echo -e "${RED}WARNING: Duplicate Primary GID 0 account found${NC}"
            fi
                awk -F: -v pgid="$pgid" '($4 == pgid) { print "User:", $1, "| GID:", $4 }' /etc/passwd
        done
    fi
    if [[ "${#DUPLICATE_USERNAMES[@]}" -gt 0 ]]; then
        echo -e "${YELLOW}Duplicate usernames found${NC}"
        local username=""
        for username in "${DUPLICATE_USERNAMES[@]}"; do
            if [[ "$username" = "root" ]]; then
                echo -e "${RED}WARNING: Duplicate ${YELLOW}root ${RED}account found${NC}"
            fi
                awk -F: -v username="$username" '($1 == username) { print $1 ":" $2 ":" $3 ":" $4 ":" $5 ":" $6 ":" $7 }' /etc/passwd
        done
    fi
    if [[ "${#DUPLICATE_GIDS[@]}" -gt 0 ]]; then
        echo -e "${YELLOW}Duplicate GIDs found${NC}"
        local gid=""
        for gid in "${DUPLICATE_GIDS[@]}"; do
            if [[ "$gid" -eq 0 ]]; then
                echo -e "${RED}WARNING: Duplicate GID 0 group found${NC}"
            fi
                awk -F: -v gid="$gid" '($3 == gid) { print "Group:", $1, "| GID:", $3 }' /etc/group
        done
    fi
    if [[ "${#DUPLICATE_GROUP_NAMES[@]}" -gt 0 ]]; then
        echo -e "${YELLOW}Duplicate group names found${NC}"
        local group_name=""
        for group_name in "${DUPLICATE_GROUP_NAMES[@]}"; do
            if [[ "$group_name" = "root" ]]; then
                echo -e "${RED}WARNING: Duplicate ${YELLOW}root ${RED}group found${NC}"
            fi
                awk -F: -v group_name="$group_name" '($1 == group_name) { print $1 ":" $2 ":" $3 }' /etc/group
        done
    fi

    # This keeps a portion of the password section, just so the user can confirm that the script isnt lying
    mapfile -t SHADOW_USERS_REDACTED < <(
        awk -F: -v OFS=":" '($2 != "" && $2 !~ /^[!*]/) { print $1, substr($2, 1, 10) "...", $3, $4, $5, $6, $7, $8, $9 }' /etc/shadow
    )
    local user=""
    echo -e "${YELLOW}Users with password configured in ${CYAN}/etc/shadow: ${NC}"
    for user in "${SHADOW_USERS_REDACTED[@]}"; do
        echo -e "$user"
    done
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
                ldap-utils ftp tnftp prelink apport gnome netcat-openbsd netcat-traditional ncat wireshark tshark tcpdump gcc make rsh-server telnetd nmap proftpd
                pure-ftpd inetutils-inetd openbsd-inetd rinetd rlinetd unbound lighttpd
            )
            for pkg in "${candidate_pkgs[@]}"; do
                dpkg-query -s "$pkg" &>/dev/null && PACKAGES+=("$pkg")
            done
            ;;
        centos|rocky|almalinux|fedora|rhel|ol)
            local -ar candidate_pkgs=(
                mcstrans setroubleshoot autofs avahi dhcp-server bind dnsmasq samba vsftpd dovecot cyrus-imapd nfs-utils ypserv cups rpcbind rsync-daemon
                net-snmp telnet-server tftp-server squid httpd nginx xinetd xorg-x11-server-common ftp openldap-clients ypbind telnet tftp @graphical-server-environment
                @workstation-product-environment netcat nmap-ncat wireshark wireshark-cli tcpdump gcc make rsh rsh-server nmap proftpd pure-ftpd unbound lighttpd
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

# Debian 2.1 & 2.2
# Requires user interaction
ask_to_remove_packages() {
    if [ ${#PACKAGES[@]} -eq 0 ]; then
        echo -e "${RED}There are no packages to remove. (did you run check_installed_packages?)${NC}"
        return 1
    fi
    echo -e "${BLUE}You will be asked if you want to remove each package${NC}"
    echo -e "${BLUE}look carefully at each, and determine if they are necessary or not.${NC}"
    local pkg=""
    for pkg in "${PACKAGES[@]}"; do
        remove_package "$PKG_MANAGER" "$pkg"
    done
}

auto_remove_packages() {
    return 1
}

install_recommended_packages() {
    local remote_logging="false"
    local extra_security="false"
    local arg=""

    for arg in "$@"; do
        case "$arg" in
            remote_logging=true) remote_logging="true" ;;
            remote_logging=false) remote_logging="false" ;;
            extra_security=true) extra_security="true" ;;
            extra_security=false) extra_security="false" ;;
            *) echo "Unrecognized argument: $arg" >&2; return 1 ;;
        esac
    done

    local pkg=""

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
            for pkg in "sudo" "apparmor" "apparmor-utils" "auditd" "audispd-plugins" "aide" "apparmor-profiles" "apparmor-profiles-extra"; do
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
            for pkg in "sudo" "libselinux" "audit" "aide" "selinux-policy" "selinux-policy-targeted"; do
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

# CIS Debian 12: 1.1.2
configure_partitions() {
    return 1
}

configure_mac() {
    return 1
}

# CIS Debian 12: 1.4.2, 1.6.4-6, 2.4.1.2-7, 2.4.1.8 (partially), 7.1.1-10, 5.1.1
# Will be rewritten to use an array of colon-separated pieces of data rather than many if statements
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

# CIS Debian 12: 4
# This is a function which will do some initialization for firewalls
# This function is not yet safe, since it doesn't really do any actions atomically/create backups of configurations
init_firewall() {
    # CIS Debian 12: 4.1
    if [ ${#FIREWALLS[@]} -eq 0 ]; then
        echo "Please install a firewall onto the system, then try again."
        return 1
    fi

    # Checks should be put in place to see if a table/chain/rule already exists
    if [[ " ${FIREWALLS[*]} " =~ " firewalld " && $DISTRO =~ ^(centos|rocky|almalinux|fedora|rhel|ol)$ ]]; then
        systemctl disable --now nftables &> /dev/null || true
        systemctl disable --now netfilter-persistent &> /dev/null || true
        systemctl disable --now ufw &> /dev/null || true
        firewall-cmd --permanent --set-default-zone=public
        firewall-cmd --permanent --zone=trusted --add-interface=lo
        firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
        firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
        firewall-cmd --permanent --add-rich-rule='rule family=ipv6 source address="::1" destination not address="::1" drop'
        firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family=ipv6 source address="::1" destination not address="::1" drop'
        systemctl enable --now firewalld
    elif [[ " ${FIREWALLS[*]} " =~ " ufw " && $DISTRO =~ ^(ubuntu|debian)$ ]]; then
        systemctl disable --now nftables &> /dev/null || true
        systemctl disable --now netfilter-persistent &> /dev/null || true
        systemctl disable --now firewalld &> /dev/null || true
        ufw allow in on lo
        ufw allow out on lo
        ufw deny in from 127.0.0.0/8
        ufw deny in from ::1
        systemctl enable --now ufw
        ufw enable
    elif [[ " ${FIREWALLS[*]} " =~ " nftables " ]]; then
        systemctl disable --now netfilter-persistent &> /dev/null || true
        systemctl disable --now firewalld &> /dev/null || true
        systemctl disable --now ufw &> /dev/null || true
        nft create table inet filter
        nft create chain inet filter INPUT '{ type filter hook input priority filter ; }'
        nft create chain inet filter FORWARD '{ type filter hook forward priority filter ; policy drop ; }'
        nft create chain inet filter OUTPUT '{ type filter hook output priority filter ; }'
        nft add rule inet filter INPUT iif lo accept
        nft add rule inet filter INPUT ip saddr 127.0.0.0/8 counter drop
        nft add rule inet filter INPUT ip protocol tcp ct state established accept
        nft add rule inet filter INPUT ip protocol udp ct state established accept
        nft add rule inet filter OUTPUT ip protocol tcp ct state new,related,established accept
        nft add rule inet filter OUTPUT ip protocol udp ct state new,related,established accept
        nft list ruleset > /etc/nftables.conf
        cp /etc/nftables.conf /etc/sysconfig/nftables.conf
        systemctl enable --now nftables
    elif [[ " ${FIREWALLS[*]} " =~ " iptables " ]]; then
        systemctl disable --now nftables &> /dev/null || true
        systemctl disable --now firewalld  &> /dev/null || true
        systemctl disable --now ufw &> /dev/null || true
        iptables -F &> /dev/null || true
        ip6tables -F &> /dev/null || true
        iptables -P FORWARD DROP
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        iptables -A INPUT -s 127.0.0.0/8 -j DROP
        iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
        iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
        iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
        iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
        iptables-save > /etc/iptables/rules.v4
        ip6tables -P FORWARD DROP
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A OUTPUT -o lo -j ACCEPT
        ip6tables -A INPUT -s ::1 -j DROP
        ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
        ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
        ip6tables-save > /etc/iptables/rules.v6
        systemctl enable --now netfilter-persistent
    fi
}

# Requires user interaction
configure_firewall() {
    if [ ${#FIREWALLS[@]} -eq 0 ]; then
        echo "Please install a firewall onto the system, then try again."
        return 1
    fi

    local -ar service_ports=(
        ftp:20/tcp
        ftp:21/tcp
        ssh:22/tcp
        smtp:25/tcp
        dns:53/udp # tcp also exists
        dhcp:67/udp
        dhcp-client:68/udp
        tftp:69/udp
        http:80/tcp
        kerberos:88/tcp # udp also exists
        pop3:110/tcp
        ntp:123/udp
        netbios-ns:137/udp
        netbios-dgm:138/udp
        netbios-ssn:139/tcp
        imap:143/tcp
        snmp:161/udp
        snmp-tra:162/udp
        ldap:389/tcp
        https:443/tcp
        samba:445/tcp
        smpts:465/tcp
        syslog:514/udp
        dhcp6-client:546/udp
        dhcp6:547/udp
        ldaps:636/tcp
        ftps:990/tcp
        imaps:993/tcp
        pops:995/tcp
        mysql:3306/tcp
        rdp:3389/tcp # udp also exists
        vnc:5900/tcp
    )

    fw_help() {
        echo -e "No changes will be made to the configuration until you enter \"finalize\""
        echo -e "Please ensure you ran ${YELLOW}fwconf${NC} before this, otherwise you may encounter firewall issues"
        echo -e "You may either enter the port number followed by the protocol (tcp | udp) in order to add an allow rule."
        echo -e "Example:"
        echo -e "Enter port/protocol, common name, or a command option: 22 tcp"
        echo -e "Alternatively, you may enter one of the generic names for a protocol below"
        echo -e "Example:"
        echo -e "Enter port/protocol or common name, or a command option: ssh"
        echo -e "Command options are as follows:"
        echo -e "${YELLOW} f${NC} : Will ask if you would like to finalize your configuration"
        echo -e "${YELLOW} e${NC} : Will exit to main menu, without saving any changes"
        echo -e "${YELLOW} h${NC} : Will show you this prompt again"
    }

    # Checks should be put in place to see if a table/chain/rule already exists
    if [[ " ${FIREWALLS[*]} " =~ " firewalld " && $DISTRO =~ ^(centos|rocky|almalinux|fedora|rhel|ol)$ ]]; then
        fw_help
        echo -e "Configuring ${RED}firewalld${NC}..."
        echo -e "${YELLOW}If ${RED}firewalld${YELLOW} is not the correct firewall, please enter n below, and ensure other firewalls are not installed."
        read -r

    elif [[ " ${FIREWALLS[*]} " =~ " ufw " && $DISTRO =~ ^(ubuntu|debian)$ ]]; then
        fw_help
        echo -e "Configuring ${RED}ufw${NC}..."
        echo -e "${YELLOW}If ${RED}ufw${YELLOW} is not the correct firewall, please enter n below, and ensure other firewalls are not installed."
        read -r

    elif [[ " ${FIREWALLS[*]} " =~ " nftables " ]]; then
        fw_help
        echo -e "Configuring ${RED}nftables${NC}..."
        echo -e "${YELLOW}If ${RED}nftables${YELLOW} is not the correct firewall, please enter n below, and ensure other firewalls are not installed."
        read -r

    elif [[ " ${FIREWALLS[*]} " =~ " iptables " ]]; then
        fw_help
        echo -e "Configuring ${RED}iptables${NC}..."
        echo -e "${YELLOW}If ${RED}iptables${YELLOW} is not the correct firewall, please enter n below, and ensure other firewalls are not installed."
        read -r

    fi
}

# CIS 6.2.3 (Ubuntu), 6.3.3 (RHEL)
configure_auditd() {
    command -v auditctl || { echo -e "${RED}Please ensure auditd is installed on your system."; return 1; }
    if [[ -d /etc/audit/rules.d && ! -f /etc/audit/rules.d/99-hardening.rules ]]; then
        cat <<- 'EOF' | tee /etc/audit/rules.d/99-hardening.rules
            # These rules were added by Michael's Linux Hardening Script
            # These rules are based off ones provided by the CIS Security benchmarks

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

            # 6.2.3.5/6.3.3.5
            -a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
            -a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
            -w /etc/issue -p wa -k system-locale
            -w /etc/issue.net -p wa -k system-locale
            -w /etc/hosts -p wa -k system-locale
            -w /etc/networks -p wa -k system-locale
            -w /etc/network -p wa -k system-locale
            -w /etc/netplan -p wa -k system-locale
            -w /etc/hostname -p wa -k system-locale
            -w /etc/sysconfig/network -p wa -k system-locale
            -w /etc/sysconfig/network-scripts/ -p wa -k system-locale
            -w /etc/NetworkManager -p wa -k system-locale

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

            # 6.2.3.14/6.3.3.14
            -w /etc/apparmor/ -p wa -k MAC-policy
            -w /etc/apparmor.d/ -p wa -k MAC-policy
            -w /etc/selinux -p wa -k MAC-policy
            -w /usr/share/selinux -p wa -k MAC-policy

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

            # 6.2.3.20/6.3.3.20
            -e 2
EOF
        augenrules --load
        augenrules --check
        systemctl enable --now auditd
    else
        echo -e "${RED}Please ensure the directory ${MAGENTA}/etc/audit/rules.d ${RED}exists.${NC}"
        return 1
    fi
}

configure_aide() {
    command -v aide || { echo -e "${RED}Please ensure AIDE is installed on your system."; return 1; }
    case "$DISTRO" in
        ubuntu|debian|linuxmint)
            aideinit
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            ;;
        centos|rocky|almalinux|fedora|rhel|ol)
            aide --init
            mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            ;;
        *)
            echo -e "${RED}Unsupported distribution${NC}"
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
# CIS Debian 12: 3.1.1
configure_sysctl() {
    local disable_ipv6="false"
    local arg=""

    for arg in "$@"; do
        case "$arg" in
            disable_ipv6=true) disable_ipv6="true" ;;
            disable_ipv6=false) disable_ipv6="false" ;;
            *) echo "Unrecognized argument: $arg" >&2; return 1 ;;
        esac
    done

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

    if [ $disable_ipv6 = "true" ]; then
        settings["net\.ipv6\.conf\.all\.disable_ipv6"]="0"
    fi

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

configure_sshd() {
    return 1
}

configure_authentication() {
    return 1
}

# Will present the main menu
main() {
    clear
    init
    [[ -f $HOME/.env ]] && source "$HOME/.env" &> /dev/null || \
        echo -e "${YELLOW}Couldn't find .env file${NC}"
    check_installed_packages
    while true; do
        printf "\n"
        printf "${GREEN}%s${NC}\n" "Welcome to Michael's Linux Hardening Script (Generic Competition Edition)"
        printf "${GREEN}%s${NC}\n" "Enter the name of an option below:"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "backup" "Will back up \"important directories\""
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "upgrade" "Will upgrade your system"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "remove" "Will ask to remove possibly unnecessary packages"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "install" "Will ask to install possibly helpful packages"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t ${RED}%s${NC}\n" "mac" "Not Yet Implemented"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t ${YELLOW}%s${NC} %s\n" "fwinit" "(EXPERIMENTAL)" "Will initialize the firewall on your system"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t ${RED}%s${NC}\n" "fwconf" "Not Yet Implemented"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "audit" "Will initialize auditd rules"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "aide" "Will initialize AIDE (may take awhile)"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t ${RED}%s${NC}\n" "fail" "Not Yet Implemented"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t ${RED}%s${NC}\n" "clam" "Not Yet Implemented"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "perms" "Will change permissions on important files for improved security"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "modules" "Will Disable unnecessary kernel modules"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "sysctl" "Will reconfigure sysctl parameters for improved security"
        printf "${BOLD}${YELLOW}%-10s${NC} :\t %s\n" "exit" "Quit program"
        printf "\n"
        while true; do
            read -rp "Enter an option: "
            case $REPLY in
                backup|b)
                    backup_directories
                    ;;
                upgrade|u)
                    upgrade_system "$PKG_MANAGER"
                    ;;
                remove|r)
                    ask_to_remove_packages
                    ;;
                install|i)
                    local option_one=""
                    local option_two=""
                    while true; do
                        read -rp "Install remote logging packages? (y/n): " option_one
                        case $option_one in
                            y) option_one="true" && break ;;
                            n) option_one="false" && break ;;
                            *) printf "${RED}%s${NC}\n" "Unrecognized option, try again" ;;
                        esac
                    done

                    while true; do
                        read -rp "Install extra security packages? (y/n): " option_two
                        case $option_two in
                            y) option_two="true" && break ;;
                            n) option_two="false" && break ;;
                            *) printf "${RED}%s${NC}\n" "Unrecognized option, try again" ;;
                        esac
                    done

                    install_recommended_packages "remote_logging=$option_one" "extra_security=$option_two"
                    option_one=""
                    option_two=""
                    ;;
                mac)
                    configure_mac
                    ;;
                fwinit)
                    init_firewall
                    ;;
                fwconf)
                    clear
                    configure_firewall
                    ;;
                audit)
                    configure_auditd
                    ;;
                aide)
                    configure_aide
                    ;;
                fail)
                    configure_fail2ban
                    ;;
                clam)
                    configure_clamav
                    ;;
                perms)
                    configure_permissions
                    ;;
                modules)
                    disable_kernel_modules
                    ;;
                sysctl)
                    local option_one=""
                    while true; do
                        read -rp "Disable IPv6? (y/n): " option_one
                        case $option_one in
                            y) option_one="true" && break ;;
                            n) option_one="false" && break ;;
                            *) printf "${RED}%s${NC}\n" "Unrecognized option, try again" ;;
                        esac
                    done

                    configure_sysctl "disable_ipv6=$option_one"
                    option_one=""
                    ;;
                exit|quit|q|ex)
                    exit 0
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