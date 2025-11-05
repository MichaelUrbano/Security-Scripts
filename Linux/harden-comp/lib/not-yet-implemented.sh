#!/bin/bash

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

# TODO: (6.1.1, 6.1.4)

# TODO: auditd autoconfig (6.2), including adding .rules files to /etc/audit/rules.d/ (specified in 6.2.3)

# TODO: Use printf instead of echo where appropriate
# TODO: Implement a logging system

# TODO: automated download of Wazuh deb/rpm

configure_sudo() {
  return 1
}

configure_sshd() {
  return 1
}

configure_authentication() {
  return 1
}
