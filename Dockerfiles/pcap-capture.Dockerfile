FROM debian:bullseye-slim

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='malcolmnetsec/pcap-capture'
LABEL org.opencontainers.image.description='Malcolm container providing network traffic capture capabilities via netsniff-ng and tcpdump'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "pcap"
ENV PGROUP "pcap"
# not dropping privileges globally: supervisord will take care of it
# for all processes, but first we need root to sure capabilities for
# traffic capturing tools are in-place before they are started.
# despite doing setcap here in the Dockerfile, the chown in
# docker-uid-gid-setup.sh will cause them to be lost, so we need
# a final check in supervisor.sh before startup
ENV PUSER_PRIV_DROP false

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

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

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
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
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} ${PUSER} && \
    mkdir -p /etc/supervisor.d && \
      chown -R ${PUSER}:${PGROUP} /etc/supervisor.d && \
      chmod -R 750 /etc/supervisor.d && \
    chown root:${PGROUP} /sbin/ethtool && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool && \
    chown root:${PGROUP} /usr/bin/tcpdump && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump && \
    chown root:${PGROUP} /usr/sbin/netsniff-ng && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip CAP_SYS_ADMIN+eip' /usr/sbin/netsniff-ng && \
    chmod 755 /usr/local/bin/*.sh

WORKDIR "$PCAP_PATH"

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/local/bin/supervisor.sh"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
