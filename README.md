# Security Scripts

This repository contains various scripts which can be used in either competitions, for hardening systems, or whatever use you may see fit.

## `harden-comp.sh`
This is a hardening script intended for use in cybersecurity competitions. It was specially made for a specific competition, though I wont specify just yet, as to not attract unwanted eyes...
### Supported Distributions:
 - Debian
 - Ubuntu
 - RHEL (Rocky, AlmaLinux, Oracle, CentOS, Fedora)
 - OpenSUSE
### Download Instructions
```
wget "https://github.com/MichaelUrbano/Security-Scripts/releases/latest/download/harden-comp.tar.xz"
```
or
```
curl -LOJ "https://github.com/MichaelUrbano/Security-Scripts/releases/latest/download/harden-comp.tar.xz"
```
then run
```
tar -xvJf harden-comp.tar.xz
cd harden-comp
sudo ./harden-comp.sh
```
You can use the `-h` option to view help information.
```
Usage: sudo ./harden-comp.sh [OPTIONS]...
Hardening and utility script for competitions

OPTIONS:
  -b, --backup DIRECTORY    send backups to/check for backups in DIRECTORY/b4
                              default value is /usr/bin
  -B, --backup-subdirectory DIRECTORY
                            change backup subdirectory
                              default value is /b4
  -c, --no-clear            disable screen clearing
  -C, --no-compress         backups will not be compressed
  -d, --distro DIST         override distribution
  -e, --no-errfail          will set +e on the script, preventing the script
                              from exiting on any non-zero status (DANGEROUS)
  -f, --firewall FW         override firewall
  -i, --init                show information from init() function, then exit
  -p, --pkg-manager PM      override package manager
  -P, --skip-pkg-chk        skips check_installed_packages() inside of main()
  -q, --run-quick           run all options under Quick, then exit
  -r, --run-backup          will run backup function
  -s, --skip-main           skips main() function
  -V, --distro-version VER  override distribution version
  -x, --xtrace              will set -x on the script, for debugging
  -h, --help                display this help and exit
      --version             output version information and exit

EXAMPLES:
  Set full backup directory as /srv/backups/b4
  sudo ./harden-comp.sh --backup /srv/backups

  Set backup directory as /srv/backups and backup subdirectory as /alt
  sudo ./harden-comp.sh -b /srv/backups -B /alt

  Set backup directory as /backups and backup subdirectory as /alt and set -x
  sudo ./harden-comp.sh --backup /backups -B /alt -x

  Set full backup directory as /usr/bin/alt and override firewall to nftables
  sudo ./harden-comp.sh --backup-subdir /alt -f nftables

  Set backup directory as /backups and backup subdirectory as /net and skip main
  sudo ./harden-comp.sh -b /backups --backup-subdir /net -s

  Override distribution to fedora, package manager to yum, and firewall to ufw
  sudo ./harden-comp.sh -d fedora -p yum -f ufw

Short options or long options can be used exclusively, or combined,
both forms are considered valid by the script.

The DIST argument can be ubuntu, debian, opensuse, centos, rocky, almalinux,
fedora, rhel, ol, or arch.
Otherwise the script will attempt to automatically determine what the system's
distribution is.

The FW argument can be firewalld, ufw, nftables, or iptables.
Otherwise the script will attempt to automatically determine what firewall the
system is using.

The PM argument can be apt, dnf, yum, zypper, or pacman.
Otherwise the script will attempt to automatically determine what
package manager the system is using.

The VER argument is an integer or float, which must be positive, and
greater than or equal to 0.
Otherwise the script will attempt to automatically determine what your
distribution version is.

Exit status:
 0  if OK,
 1  if any problems occur.

Part of Security Scripts, by Michael Urbano.
For more information, please visit GitHub.
<https://github.com/MichaelUrbano/Security-Scripts>.
Report bugs, vulnerabilties, or other issues to git@michaelurbano.com
```
Disclaimer, these scripts have not been thouroughly tested on all versions of the distributions listed, some features may not work as intended on older versions.
# Contact
#### Concerns or bugs? 
Use the Issues page
#### Questions or Vulnerability Disclosures? 
Email me at git@michaelurbano.com
