# Sets up journald and some auditd rules
{
  services.journald.extraConfig = ''
    SystemMaxUse=1G
    SystemKeepFree=500M
    RuntimeMaxUse=200M
    RuntimeKeepFree=50M
    MaxFileSec=1month
    Compress=yes
  '';

  security = {
    auditd.enable = true;

    audit = {
      enable = true;
      rules = [
        # 6.2.3.1/6.3.3.1
        "-w /etc/sudoers -p wa -k scope"

        # 6.2.3.2/6.3.3.2
        "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"
        "-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation"

        # 6.2.3.3/6.3.3.3
        "-w /var/log/sudo.log -p wa -k sudo_log_file"

        # 6.2.3.4/6.3.3.4
        "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
        "-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change"
        "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change"
        "-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change"

        # 6.2.3.5/6.3.3.5 (partial)
        "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
        "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
        "-w /etc/issue -p wa -k system-locale"
        "-w /etc/hosts -p wa -k system-locale"

        # 6.2.3.6/6.3.3.6
        # Not yet implemented

        # 6.2.3.7/6.3.3.7
        "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
        "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
        "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
        "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"

        # 6.2.3.8/6.3.3.8
        "-w /etc/group -p wa -k identity"
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/nsswitch.conf -p wa -k identity"
        "-w /etc/pam.d -p wa -k identity"

        # 6.2.3.9/6.3.3.9
        "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod"
        "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"
        "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod"

        # 6.2.3.10/6.3.3.10
        "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts"
        "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"

        # 6.2.3.11/6.3.3.11
        "-w /var/log/wtmp -p wa -k session"
        "-w /var/log/btmp -p wa -k session"

        # 6.2.3.12/6.3.3.12
        "-w /var/log/lastlog -p wa -k logins"

        # 6.2.3.13/6.3.3.13
        "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete"
        "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete"

        # 6.2.3.19/6.3.3.19
        "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules"

        "-a always,exit -S all -F path=/run/current-system/sw/bin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-usermod"
        "-a always,exit -S all -F path=/run/current-system/sw/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-chage"
        "-a always,exit -S all -F path=/run/current-system/sw/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -k perm_mod"
      ];
    };
  };
}
