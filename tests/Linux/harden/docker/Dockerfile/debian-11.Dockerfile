FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y bats expect sudo iptables iproute2 net-tools tar gzip
WORKDIR /workspace
COPY . .