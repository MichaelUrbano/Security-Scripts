# Mount /tmp and /dev/shm as tmpfs filesystems with more restrictive options
{
  boot.tmp.useTmpfs = true;
  fileSystems."/dev/shm" = {
    device = "tmpfs";
    fsType = "tmpfs";
    options = [
      "rw"
      "nosuid"
      "nodev"
      "noexec"
    ];
  };
}
