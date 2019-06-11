FROM debian:buster-slim AS build

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

ARG PCAP_ENABLE_TCPDUMP=false
ARG PCAP_ENABLE_NETSNIFF=false
# PCAP_IFACE=comma-separated list of capture interfaces
ARG PCAP_IFACE=eth0
ARG PCAP_NETSNIFF_MAGIC=0xa1b2c3d4
ARG PCAP_TCPDUMP_FILENAME_PATTERN=%Y%m%d%H%M%S.pcap
ARG PCAP_ROTATE_MINUTES=30
ARG PCAP_ROTATE_MEGABYTES=500
ARG PCAP_PATH=/pcap
ARG PCAP_FILTER=
ARG PCAP_SNAPLEN=0
ARG PCAP_USER=pcap

ENV PCAP_ENABLE_TCPDUMP $PCAP_ENABLE_TCPDUMP
ENV PCAP_ENABLE_NETSNIFF $PCAP_ENABLE_NETSNIFF
ENV PCAP_IFACE $PCAP_IFACE
ENV PCAP_NETSNIFF_MAGIC $PCAP_NETSNIFF_MAGIC
ENV PCAP_TCPDUMP_FILENAME_PATTERN $PCAP_TCPDUMP_FILENAME_PATTERN
ENV PCAP_ROTATE_MINUTES $PCAP_ROTATE_MINUTES
ENV PCAP_ROTATE_MEGABYTES $PCAP_ROTATE_MEGABYTES
ENV PCAP_PATH $PCAP_PATH
ENV PCAP_FILTER $PCAP_FILTER
ENV PCAP_SNAPLEN $PCAP_SNAPLEN
ENV PCAP_USER $PCAP_USER

ADD pcap-capture/supervisord.conf /etc/supervisord.conf
ADD pcap-capture/scripts/*.sh /usr/local/bin/
ADD pcap-capture/templates/*.template /etc/supervisor.d/

RUN apt-get update && \
    apt-get install --no-install-recommends -y -q \
      bc \
      ethtool \
      libcap2-bin \
      netsniff-ng \
      procps \
      psmisc \
      supervisor \
      tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/log/supervisor /etc/supervisor.d && \
    groupadd --gid 1000 $PCAP_USER && \
      useradd -M --uid 1000 --gid 1000 $PCAP_USER && \
    chown root:$PCAP_USER /sbin/ethtool && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool && \
    chown root:$PCAP_USER /usr/sbin/tcpdump && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/sbin/tcpdump && \
    chown root:$PCAP_USER /usr/sbin/netsniff-ng && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip CAP_SYS_ADMIN+eip' /usr/sbin/netsniff-ng && \
    chmod 755 /usr/local/bin/*.sh

WORKDIR "$PCAP_PATH"

CMD ["/usr/local/bin/supervisor.sh"]
