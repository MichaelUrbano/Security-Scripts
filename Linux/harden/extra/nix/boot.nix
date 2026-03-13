# Will disable kernel modules and set some kernel parameters relating to networking
let
  disableIPv6 = false; # Will disable IPv6 on the system
  allowBreakage = false; # Could break networking for containers/networking in cloud environments
in
{
  boot = {
    blacklistedKernelModules = [
      "cramfs"
      "freevxfs"
      "hfs"
      "hfsplus"
      "jffs2"
      "squashfs"
      "udf"
      "ceph"
      "gfs2"
      "nfsd"
      "dccp"
      "tipc"
      "rds"
      "sctp"
      "atm"
      "can"
    ];

    kernel.sysctl = {
      "net.ipv4.conf.all.accept_redirects" = 0;
      "net.ipv4.conf.default.accept_redirects" = 0;
      "net.ipv6.conf.all.accept_redirects" = 0;
      "net.ipv6.conf.default.accept_redirects" = 0;
      "net.ipv4.conf.all.rp_filter" = 1;
      "net.ipv4.conf.default.rp_filter" = 1;
      "net.ipv4.conf.all.log_martians" = 1;
      "net.ipv4.conf.default.log_martians" = 1;
      # Usually set to correct values already, this just explicitly declares it just in case
      "net.ipv4.icmp_ignore_bogus_error_responses" = 1;
      "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
      "net.ipv4.tcp_syncookies" = 1;
    }
    // (
      if allowBreakage then
        {
          "net.ipv4.ip_forward" = 0;
          "net.ipv6.conf.all.forwarding" = 0;
          "net.ipv4.conf.all.send_redirects" = 0;
          "net.ipv4.conf.default.send_redirects" = 0;
          "net.ipv4.conf.all.secure_redirects" = 0;
          "net.ipv4.conf.default.secure_redirects" = 0;
          "net.ipv4.conf.all.accept_source_route" = 0;
          "net.ipv4.conf.default.accept_source_route" = 0;
          "net.ipv6.conf.all.accept_source_route" = 0;
          "net.ipv6.conf.default.accept_source_route" = 0;
          "net.ipv6.conf.all.accept_ra" = 0;
          "net.ipv6.conf.default.accept_ra" = 0;
        }
      else
        { }
    )
    // (
      if disableIPv6 then
        {
          "net.ipv6.conf.all.disable_ipv6" = 1;
          "net.ipv6.conf.default.disable_ipv6" = 1;
        }
      else
        {
          "net.ipv6.conf.all.disable_ipv6" = 0;
          "net.ipv6.conf.default.disable_ipv6" = 0;
        }
    );
  };
}
