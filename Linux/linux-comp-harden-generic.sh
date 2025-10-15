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

# TODO: sysctl should do the following in a function:
# kernel.randomize_va_space = 2
# kernel.yama.ptrace_scope = 2
# fs.suid_dumpable = 0 (and in /etc/security/limits.d/ add: * hard core 0)
# net.ipv6.conf.all.disable_ipv6 = 0 (optional, ipv6 might be needed)
# net.ipv4.icmp_ignore_bogus_error_responses = 1
# net.ipv4.icmp_echo_ignore_broadcasts = 1
# net.ipv4.conf.all.rp_filter = 2
# net.ipv4.conf.default.rp_filter = 2
# net.ipv4.conf.all.log_martians = 1
# net.ipv4.conf.default.log_martians = 1
# net.ipv4.tcp_syncookies = 1

# TODO: Service auditor, checking if packages/services exist on the system, and if they should be removed/disabled (2.1)

# TODO: (5.4.2)

# TODO: (5.4.3.1, 5.4.3.2-3(?))

# TODO: (6.1.1, 6.1.4), (6.1.2-3 (maybe))

# TODO: auditd autoconfig (6.2), including adding .rules files to /etc/audit/rules.d/ (specified in 6.2.3)

# TODO: aide autoconfig (6.3)

# TODO: Supplementary security tools autoconfig (fail2ban, ossec, clamav, chkrootkit, lynis)

# TODO: Allow for overriding variables (DISTRO, PKG_MANAGER, FIREWALLS)

# I will add set -e to this script, once it becomes important to make it stable and not possibly obliterate your system

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root, or with sudo." >&2
    exit 1
fi

source "$HOME/.env" || true

# Sets up variables, and checks for important system information
init() {
    # Set ANSI Escape Code variables for different colors in the terminal
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m]'
    CYAN='\033[0;36m]'
    NC='\033[0m'

    # Determine distro being used
    if [ -f /etc/os-release ]; then
        # freedesktop.org and systemd
        . /etc/os-release
        DISTRO=$ID
        VER=$VERSION_ID
    elif type lsb_release > /dev/null 2>&1; then
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
    echo -e "${GREEN}Distribution ID:${NC} $DISTRO"

    # Choose correct package manager for distro
    case "$DISTRO" in
        ubuntu|debian|linuxmint)
            PKG_MANAGER="apt"
            ;;
        centos|rocky|almalinux|fedora|ol)
            PKG_MANAGER="yum"
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
    FIREWALLS=""

    # firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALLS+="firewalld "
    fi

    # ufw
    if command -v ufw >/dev/null 2>&1; then
        FIREWALLS+="ufw "
    fi

    # nftables
    if command -v nft >/dev/null 2>&1; then
        FIREWALLS+="nftables "
    fi

    # iptables
    if command -v iptables >/dev/null 2>&1; then
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
            apt remove -y "$package_name"
            ;;
        dnf)
            echo "Using dnf to remove $package_name..."
            dnf remove -y "$package_name"
            ;;
        yum)
            echo "Using yum to remove $package_name..."
            yum remove -y "$package_name"
            ;;
        zypper)
            echo "Using zypper to remove $package_name..."
            zypper remove -y "$package_name"
            ;;
        pacman)
            echo "Using pacman to remove $package_name..."
            pacman -R --noconfirm "$package_name"
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

install_recommended_software() {
    case "$DISTRO" in
        debian)
        # CIS Debian 12: 
            install_package "$PKG_MANAGER" "sudo"
            install_package "$PKG_MANAGER" "apparmor"
            #install_package "$PKG_MANAGER" "systemd-journal-remote"
            #install_package "$PKG_MANAGER" "rsyslog"
            install_package "$PKG_MANAGER" "auditd"
            install_package "$PKG_MANAGER" "aide"
            ;;
        *)
            echo "We don't know what your package manager is, sorry"
            ;;
    esac
}

remove_recommended_software() {
    case "$DISTRO" in
        debian)
            # CIS Debian 12: 2.2.1, 2.2.2, 2.2.3, 2.2.4, 2.2.6
            # 2.2.5 Missing, ldap may be needed(?)
            remove_package "$PKG_MANAGER" "nis"
            remove_package "$PKG_MANAGER" "rsh-client"
            remove_package "$PKG_MANAGER" "talk"
            remove_package "$PKG_MANAGER" "telnet"
            remove_package "$PKG_MANAGER" "tnftp"
            remove_package "$PKG_MANAGER" "netcat"
            ;;
        *)
            echo "Nothing here yet, sorry."
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
    local flag

    if [ -d "/etc" ]; then
        echo -e "Backing up ${YELLOW}/etc${NC}"
        local etc_backup="${backup_path}/ettc-$(date +%b-%d-%H.%M.%S)"
        tar -cf "$etc_backup" /etc
        for flag in u a i; do
            chattr +"$flag" "$etc_backup" >/dev/null 2>&1 || true
        done
    fi
    if [ -d "/var/www/html" ]; then
        echo -e "Backing up ${YELLOW}/var/www/html${NC}"
        local html_backup="${backup_path}/httml-$(date +%b-%d-%H.%M.%S)"
        tar -cf "$html_backup" /var/www/html >/dev/null 2>&1 || true
        for flag in u a i; do
            chattr +"$flag" "$html_backup" >/dev/null 2>&1 || true
        done
    fi
    if [ -d "/opt" ]; then
        echo -e "Backing up ${YELLOW}/opt${NC}"
        local opt_backup="${backup_path}/oppt-$(date +%b-%d-%H.%M.%S)"
        tar -cf "$opt_backup" /opt >/dev/null 2>&1 || true
        for flag in u a i; do
            chattr +"$flag" "$opt_backup" >/dev/null 2>&1 || true
        done
    fi
    echo -e "Done. You can find your backups at ${YELLOW}${backup_path}${NC}"
}

# CIS Debian 12: 1.4.2, 1.6.4-6, 2.4.1.2-7, 2.4.1.8 (partially), 7.1.1-10, 5.1.1
configure_permissions() {
    # 1.4.2
    chown root:root /boot/grub/grub.cfg && chmod 0600 /boot/grub/grub.cfg

    # 1.6.4-6
    [ -e /etc/motd ] && chown root:root /etc/motd && chmod 644 /etc/motd
    [ -e /etc/issue ] && chown root:root /etc/issue && chmod 644 /etc/issue
    [ -e /etc/issue.net ] && chown root:root /etc/issue.net && chmod 644 /etc/issue.net

    # 2.4.1.2-7
    [ -e /etc/crontab ] && chown root:root /etc/crontab && chmod 600 /etc/crontab
    [ -e /etc/cron.hourly ] && chown root:root /etc/cron.hourly && chmod 700 /etc/cron.hourly
    [ -e /etc/cron.daily ] && chown root:root /etc/cron.daily && chmod 700 /etc/cron.daily
    [ -e /etc/cron.weekly ] && chown root:root /etc/cron.weekly && chmod 700 /etc/cron.weekly
    [ -e /etc/cron.monthly ] && chown root:root /etc/cron.monthly && chmod 700 /etc/cron.monthly
    [ -e /etc/cron.d ] && chown root:root /etc/cron.d && chmod 700 /etc/cron.d

    # 2.4.1.8 (partially) (possible issues on systems with crontab group)
    #[ -f /etc/cron.allow] && chown root:root /etc/cron.allow && chmod 640 /etc/cron.allow
    #[ -f /etc/cron.deny] && chown root:root /etc/cron.deny && chmod 640 /etc/cron.deny

    # 7.1.1-10
    chown root:root /etc/passwd && chmod 644 /etc/passwd
    chown root:root /etc/passwd- && chmod 644 /etc/passwd-
    chown root:root /etc/group && chmod 644 /etc/group
    chown root:root /etc/group- && chmod 644 /etc/group-
    case "$DISTRO" in
        debian|ubuntu)
            chown root:shadow /etc/shadow && chmod 640 /etc/shadow
            chown root:shadow /etc/shadow- && chmod 640 /etc/shadow-
            chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow
            chown root:shadow /etc/gshadow- && chmod 640 /etc/gshadow-
            ;;
        centos|rocky|almalinux|fedora|ol|opensuse*)
            chown root:root /etc/shadow && chmod 000 /etc/shadow
            chown root:root /etc/shadow- && chmod 000 /etc/shadow-
            chown root:root /etc/gshadow && chmod 000 /etc/gshadow
            chown root:root /etc/gshadow- && chmod 000 /etc/gshadow-
            ;;
        *)
            echo "go configure /etc/shadow and /etc/gshadow yourself buddy"
            ;;
    esac
    chown root:root /etc/shells && chmod 644 /etc/shells
    [ -e /etc/security/opasswd ] && chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd
    [ -e /etc/security/opasswd.old ] && chown root:root /etc/security/opasswd.old && chmod 600 /etc/security/opasswd.old

    # 5.1.1
    [ -e /etc/ssh/sshd_config ] && chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config
    if [ -d /etc/ssh/sshd_config.d ]; then
        for file in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$file" ] || continue
            chown root:root "$file"
            chmod 600 "$file"
        done
    fi
}

# CIS DEBIAN 12: 1.1.1.1-5,8-9, 3.2
# MANUAL: 1.1.1.10
# Will disable unnecessary kernel modules
disable_kernel_modules() {
    modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage" "dccp" "tipc" "rds" "sctp")
    local custom_blacklist="/etc/modprobe.d/custom-blacklist.conf"
    local mod
    touch "$custom_blacklist"

    # Check for duplicates, then add an entry if it doesn't exist.
    for mod in "{$modules[@]}"; do
        if ! grep -qE "^install[[:space:]]+$mod[[:space:]]+" "$custom_blacklist"; then
            echo "install $mod /bin/false" >> "$custom_blacklist"
        fi
    done
}


# Will present the main menu
main() { 
    init
}

main