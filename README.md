# Security Scripts

These scripts are actively being worked on, if you would like to get the only one currently present in the repository:

`wget https://raw.githubusercontent.com/MichaelUrbano/Security-Scripts/refs/heads/main/Linux/linux-comp-harden-generic.sh`

If you want to change some of the variables within the script, create a `.env` file within the `/root` directory, in which you can set the following variables:
- `BAKDIR`: Will change the directory used for backups. Backups will be placed within a child directory (`b4`), located in your specified directory.
- `DISTRO`: Lets you set the distro to `debian`, `ubuntu`, `centos`, `rocky`, `almalinux`, `fedora`, `rhel`, `ol`, and more.
- `PKG_MANAGER`: Sets the package manager you should be using. Can be `apt`, `dnf`, `yum`, and `zypper`