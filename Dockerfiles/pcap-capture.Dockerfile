FROM debian:12-slim

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/pcap-capture'
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
ENV PUSER_RLIMIT_UNLOCK true

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG PCAP_ENABLE_TCPDUMP=false
ARG PCAP_ENABLE_NETSNIFF=false
# PCAP_IFACE=comma-separated list of capture interfaces
ARG PCAP_IFACE=lo
ARG PCAP_IFACE_TWEAK=false
ARG PCAP_NETSNIFF_MAGIC=0xa1b2c3d4
ARG PCAP_TCPDUMP_FILENAME_PATTERN=%Y%m%d%H%M%S.pcap
ARG PCAP_ROTATE_MINUTES=10
ARG PCAP_ROTATE_MEGABYTES=4096
ARG PCAP_PATH=/pcap
ARG PCAP_FILTER=
ARG PCAP_SNAPLEN=0

ENV PCAP_ENABLE_TCPDUMP $PCAP_ENABLE_TCPDUMP
ENV PCAP_ENABLE_NETSNIFF $PCAP_ENABLE_NETSNIFF
ENV PCAP_IFACE $PCAP_IFACE
ENV PCAP_IFACE_TWEAK $PCAP_IFACE_TWEAK
ENV PCAP_NETSNIFF_MAGIC $PCAP_NETSNIFF_MAGIC
ENV PCAP_TCPDUMP_FILENAME_PATTERN $PCAP_TCPDUMP_FILENAME_PATTERN
ENV PCAP_ROTATE_MINUTES $PCAP_ROTATE_MINUTES
ENV PCAP_ROTATE_MEGABYTES $PCAP_ROTATE_MEGABYTES
ENV PCAP_PATH $PCAP_PATH
ENV PCAP_FILTER $PCAP_FILTER
ENV PCAP_SNAPLEN $PCAP_SNAPLEN

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
COPY --chmod=755 shared/bin/nic-capture-setup.sh /usr/local/bin/
ADD pcap-capture/supervisord.conf /etc/supervisord.conf
ADD pcap-capture/scripts/*.sh /usr/local/bin/
ADD pcap-capture/templates/*.template /etc/supervisor.d/

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install --no-install-recommends -y -q \
      bc \
      ethtool \
      libcap2-bin \
      netsniff-ng \
      openssl \
      procps \
      psmisc \
      rsync \
      supervisor \
      tcpdump \
      tini && \
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

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "pcap-capture"]

CMD ["/usr/local/bin/supervisor.sh"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
