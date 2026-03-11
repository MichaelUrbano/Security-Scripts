FROM opensuse/leap:latest
RUN zypper refresh && \
    zypper install -y bats expect sudo iptables iproute2 net-tools tar gzip
WORKDIR /workspace
COPY . .