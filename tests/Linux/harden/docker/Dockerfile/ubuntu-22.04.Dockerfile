FROM ubuntu:22.04
# Image wont build because it hangs on an interactive prompt in apt-get
# Have to set the timezone ahead of time because of this
ENV DEBIAN_FRONTEND=noninteractive
RUN echo Etc/UTC > /etc/timezone && \
    ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime && \
    apt-get update && \
    apt-get install -y bats expect sudo iptables iproute2 net-tools tar gzip
WORKDIR /workspace
COPY . .