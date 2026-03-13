# Hardened OpenSSH Server configuration
{
  services.openssh = {
    settings = {
      PermitRootLogin = "no";
      LogLevel = "VERBOSE";
      UsePAM = true;
    };

    extraConfig = ''
      ClientAliveInterval 15
      ClientAliveCountMax 3
      DisableForwarding yes
      GSSAPIAuthentication no
      HostbasedAuthentication no
      IgnoreRhosts yes
      LoginGraceTime 60
      MaxAuthTries 4
      MaxSessions 10
      MaxStartups 10:30:60
      PermitEmptyPasswords no
      PermitUserEnvironment no
    '';
  };
}
