FROM oraclelinux:10
RUN dnf install -y oracle-epel-release-el10 || true && \
    dnf update -y && \
    (dnf install -y bats expect sudo iptables iproute2 iproute net-tools tar gzip --allowerasing || \
     dnf install -y bats expect sudo iptables iproute net-tools tar gzip)
WORKDIR /workspace
COPY . .