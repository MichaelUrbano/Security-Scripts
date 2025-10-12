#!/bin/bash

# determine distro being used
if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    DISTRO=$NAME
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
echo "Distribution: $DISTRO"
DISTRO=$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')

# choose correct package manager for distro
case "$DISTRO" in
    ubuntu|debian|mint)
        PKG_MANAGER="apt"
        ;;
    centos|rocky|almalinux|fedora)
        PKG_MANAGER="yum"
        ;;
    arch)
        PKG_MANAGER="pacman"
        ;;
    opensuse*)
        PKG_MANAGER="zypper"
        ;;
    *)
        PKG_MANAGER="unsupported"
        ;;
esac

echo "Packge Manager: $PKG_MANAGER"

# find firewalls installed on the system
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

echo "Installed firewalls: $FIREWALLS"

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
        pacman)
            echo "Using pacman to install $package_name..."
            pacman -Syu --noconfirm "$package_name"
            ;;
        zypper)
            echo "Using zypper to install $package_name..."
            zypper install -y "$package_name"
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
        pacman)
            echo "Using pacman to remove $package_name..."
            pacman -R --noconfirm "$package_name"
            ;;
        zypper)
            echo "Using zypper to remove $package_name..."
            zypper remove -y "$package_name"
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
        pacman)
            echo "Using pacman to upgrade system..."
            pacman -Syu --noconfirm
            ;;
        zypper)
            echo "Using zypper to upgrade system..."
            zypper up
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
        # Only confirmed working with Debian 12, may vary with other versions
            install_package "$PKG_MANAGER" "sudo"
            install_package "$PKG_MANAGER" "apparmor"
            install_package "$PKG_MANAGER" "systemd-journal-remote"
            install_package "$PKG_MANAGER" "rsyslog"
            install_package "$PKG_MANAGER" "auditd"
            install_package "$PKG_MANAGER" "aide"
            ;;
        *)
            echo "Nothing here yet, sorry."
            ;;
    esac
}

remove_recommended_software() {
    case "$DISTRO" in
        debian)
            remove_package "$PKG_MANAGER" "nis"
            remove_package "$PKG_MANAGER" "rsh-client"
            remove_package "$PKG_MANAGER" "talk"
            remove_package "$PKG_MANAGER" "telnet"
            remove_package "$PKG_MANAGER" "tnftp"
            ;;
        *)
            echo "Nothing here yet, sorry."
            ;;
    esac
}

configure_permissions() {
    [ -e /etc/crontab ] && chown root:root /etc/crontab && chmod 600 /etc/crontab
    [ -e /etc/cron.hourly ] && chown root:root /etc/cron.hourly && chmod 700 /etc/cron.hourly
    [ -e /etc/cron.daily ] && chown root:root /etc/cron.daily && chmod 700 /etc/cron.daily
    [ -e /etc/cron.weekly ] && chown root:root /etc/cron.weekly && chmod 700 /etc/cron.weekly
    [ -e /etc/cron.monthly ] && chown root:root /etc/cron.monthly && chmod 700 /etc/cron.monthly
    [ -e /etc/cron.d ] && chown root:root /etc/cron.d && chmod 700 /etc/cron.d
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
        centos|rocky|almalinux|fedora|opensuse*)
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
    [ -e /etc/ssh/sshd_config ] && chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config
    if [ -d /etc/ssh/sshd_config.d ]; then
        for file in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$file" ] || continue
            chown root:root "$file"
            chmod 600 "$file"
        done
    fi

}

# currently does nothing
disable_kernel_modules() {
    modules=("cramfs" "freevxfs" "hfs" "hfsplus" "jffs2" "udf" "usb-storage")
    local fs_blacklist="/etc/modprobe.d/fs-blacklist.conf"
    return 1
}