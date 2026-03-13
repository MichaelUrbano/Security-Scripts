# Enables AppArmor; not included in default.nix, given AppArmor on NixOS is still immature
{
  security.apparmor = {
    enable = true;
  };
}
