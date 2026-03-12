FROM opensuse/leap:15
RUN zypper refresh && \
    zypper install -y bats expect sudo iptables iproute2 net-tools tar gzip
WORKDIR /workspace
COPY . .