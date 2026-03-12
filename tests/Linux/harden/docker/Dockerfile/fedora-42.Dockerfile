FROM fedora:42
RUN dnf update -y && \
    (dnf install -y bats expect sudo iptables iproute2 iproute net-tools tar gzip --allowerasing || \
     dnf install -y bats expect sudo iptables iproute net-tools tar gzip)
WORKDIR /workspace
COPY . .