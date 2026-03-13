# Harden sudo & log its usage
{
  security.sudo = {
    configFile = ''
      Defaults use_pty
      Defaults logfile="/var/log/sudo.log"
      Defaults env_reset, timestamp_timeout=15
    '';
  };
}
