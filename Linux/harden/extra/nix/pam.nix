# Disable unneeded commands, assuming users are managed through NixOS Configuration
{
  security.pam.services = {
    su.enable = false;
    chfn.enable = false;
    chsh.enable = false;
    chpasswd.enable = false;
    groupadd.enable = false;
    groupdel.enable = false;
    groupmems.enable = false;
    groupmod.enable = false;
  };
}
