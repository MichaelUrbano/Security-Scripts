# Replace with the distribution you want to use here.
FROM opensuse/tumbleweeed:latest

# Replace with commands needed to update packages & install dependencies
# Dependencies for running tests include:
    # bats
    # expect
    # sudo
    # iproute/iproute2 (for ss command)
    # tar
    # gzip
    # One or more of the following firewalls
        # firewalld
        # ufw
        # nftables
        # iptables
# The names for these packages may vary between distributions,
# ensure you have the correct names for each package when performing installations.
RUN zypper refresh && \
    zypper install -y bats expect sudo iptables iproute2 net-tools tar gzip
WORKDIR /workspace
COPY . .