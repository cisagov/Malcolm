# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

FROM debian:13-slim

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/arkime'
LABEL org.opencontainers.image.description='Malcolm container providing Arkime'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "arkime"
ENV PGROUP "arkime"
# not dropping privileges globally: supervisord will take care of it
# for all processes, but first we need root to sure capabilities for
# traffic capturing tools are in-place before they are started.
# despite doing setcap here in the Dockerfile, the chown in
# docker-uid-gid-setup.sh will cause them to be lost, so we need
# a final check in docker_entrypoint.sh before startup
ENV PUSER_PRIV_DROP false
ENV PUSER_RLIMIT_UNLOCK true
USER root

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ENV ARKIME_DIR "/opt/arkime"
ENV ARKIME_VERSION "5.8.3"
ENV ARKIME_DEB_URL "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/arkime_${ARKIME_VERSION}-1.debian13_XXX.deb"
ENV ARKIME_JA4_SO_URL "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/ja4plus.XXX.so"
ENV ARKIME_LOCALELASTICSEARCH no
ENV ARKIME_INET yes

ARG MALCOLM_USERNAME=admin
ARG ARKIME_ECS_PROVIDER=arkime
ARG ARKIME_ECS_DATASET=session
ARG ARKIME_AUTO_ANALYZE_PCAP_FILES=false
ARG ARKIME_AUTO_ANALYZE_PCAP_THREADS=1
ARG ARKIME_PACKET_THREADS=2
ARG ARKIME_TPACKETV3_NUM_THREADS=2
ARG WISE=on
ARG VIEWER=on
ARG ARKIME_SSL=true
ARG ARKIME_VIEWER_PORT=8005
#Whether or not Arkime is in charge of deleting old PCAP files to reclaim space
ARG MANAGE_PCAP_FILES=false
ARG ARKIME_PCAP_PROCESSOR=true
ARG ARKIME_LIVE_CAPTURE=false
ARG ARKIME_ROTATED_PCAP=true
ARG ARKIME_COMPRESSION_TYPE=none
ARG ARKIME_COMPRESSION_LEVEL=0

#Whether or not to auto-tag logs based on filename
ARG AUTO_TAG=true
ARG PCAP_PIPELINE_VERBOSITY=""
ARG PCAP_MONITOR_HOST=pcap-monitor
ARG PCAP_NODE_NAME=malcolm
ARG PCAP_PROCESSED_DIRECTORY=/data/pcap/processed
ARG MAXMIND_GEOIP_DB_LICENSE_KEY=""
ARG MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL=""

# Declare envs vars for each arg
ENV MALCOLM_USERNAME $MALCOLM_USERNAME
# this needs to be present, but is unused as nginx is going to handle auth for us
ENV ARKIME_PASSWORD "ignored"
ENV ARKIME_ECS_PROVIDER $ARKIME_ECS_PROVIDER
ENV ARKIME_ECS_DATASET $ARKIME_ECS_DATASET
ENV ARKIME_DIR "/opt/arkime"
ENV ARKIME_AUTO_ANALYZE_PCAP_FILES $ARKIME_AUTO_ANALYZE_PCAP_FILES
ENV ARKIME_AUTO_ANALYZE_PCAP_THREADS $ARKIME_AUTO_ANALYZE_PCAP_THREADS
ENV ARKIME_PACKET_THREADS $ARKIME_PACKET_THREADS
ENV ARKIME_TPACKETV3_NUM_THREADS $ARKIME_TPACKETV3_NUM_THREADS
ENV ARKIME_PCAP_PROCESSOR $ARKIME_PCAP_PROCESSOR
ENV ARKIME_LIVE_CAPTURE $ARKIME_LIVE_CAPTURE
ENV ARKIME_COMPRESSION_TYPE $ARKIME_COMPRESSION_TYPE
ENV ARKIME_COMPRESSION_LEVEL $ARKIME_COMPRESSION_LEVEL
ENV ARKIME_ROTATED_PCAP $ARKIME_ROTATED_PCAP
ENV WISE $WISE
ENV VIEWER $VIEWER
ENV ARKIME_SSL $ARKIME_SSL
ENV ARKIME_VIEWER_PORT $ARKIME_VIEWER_PORT
ENV MANAGE_PCAP_FILES $MANAGE_PCAP_FILES
ENV AUTO_TAG $AUTO_TAG
ENV PCAP_PIPELINE_VERBOSITY $PCAP_PIPELINE_VERBOSITY
ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST
ENV PCAP_NODE_NAME $PCAP_NODE_NAME
ENV PCAP_PROCESSED_DIRECTORY $PCAP_PROCESSED_DIRECTORY

ADD --chmod=644 arkime/requirements.txt /usr/local/src/

RUN export DEBARCH=$(dpkg --print-architecture) && \
    sed -i "s/main$/main contrib non-free/g" /etc/apt/sources.list.d/debian.sources && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
      bc \
      bzip2 \
      curl \
      ethtool \
      file \
      geoip-bin \
      git \
      gzip \
      inotify-tools \
      jq \
      libcap2-bin \
      libglib2.0-0 \
      libjson-perl \
      libkrb5-3 \
      liblua5.4-0 \
      libmaxminddb0 \
      libpcap0.8 \
      libpcre2-8-0 \
      librdkafka1 \
      libssl3 \
      libtool \
      libwww-perl \
      libyaml-0-2 \
      libyaml-dev \
      libyara10 \
      libzmq5 \
      lua5.4 \
      lzma \
      p7zip-full \
      procps \
      psmisc \
      python3 \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      rsync \
      tar \
      tini \
      unrar \
      unzip \
      vim-tiny \
      wget \
      xz-utils \
      zlib1g && \
    cd /tmp && \
      curl -fsSL -o ./arkime.deb "$(echo "${ARKIME_DEB_URL}" | sed "s/XXX/${DEBARCH}/g")" && \
      dpkg -i /tmp/arkime.deb && \
      rm -f ${ARKIME_DIR}/etc/*.systemd.service && \
    mkdir -p "${ARKIME_DIR}"/plugins "${ARKIME_DIR}"/rules && \
      curl -fsSL -o "${ARKIME_DIR}/plugins/ja4plus.${DEBARCH}.so" "$(echo "${ARKIME_JA4_SO_URL}" | sed "s/XXX/${DEBARCH}/g")" && \
      chmod 755 "${ARKIME_DIR}/plugins/ja4plus.${DEBARCH}.so" && \
    python3 -m pip install --break-system-packages --no-compile --no-cache-dir -r /usr/local/src/requirements.txt && \
    ln -sfr $ARKIME_DIR/bin/npm /usr/local/bin/npm && \
      ln -sfr $ARKIME_DIR/bin/node /usr/local/bin/node && \
      ln -sfr $ARKIME_DIR/bin/npx /usr/local/bin/npx && \
    apt-get -q -y --purge remove git gcc gcc-12 cpp cpp-12 && \
      apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# add configuration and scripts
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 shared/bin/self_signed_key_gen.sh /usr/local/bin/
ADD --chmod=755 shared/bin/maxmind-mmdb-download.sh /usr/local/bin/
ADD --chmod=755 shared/bin/nic-capture-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/opensearch_status.sh /usr/local/bin/
ADD --chmod=755 shared/bin/pcap_processor.py /usr/local/bin/
ADD --chmod=644 shared/bin/pcap_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
ADD --chmod=644 scripts/malcolm_constants.py /usr/local/bin/
ADD --chmod=644 shared/bin/watch_common.py /usr/local/bin/
ADD --chmod=644 arkime/supervisord.conf /etc/supervisord.conf
ADD --chmod=755 container-health-scripts/arkime.sh /usr/local/bin/container_health.sh
ADD arkime/scripts /usr/local/bin/
ADD arkime/etc $ARKIME_DIR/etc/
ADD --chmod=644 arkime/rules/*.yml $ARKIME_DIR/rules/
ADD --chmod=644 arkime/wise/source.*.js $ARKIME_DIR/wiseService/

# MaxMind now requires a (free) license key to download the free versions of
# their GeoIP databases. This should be provided as a build argument.
#   see https://dev.maxmind.com/geoip/geoipupdate/#Direct_Downloads
#   see https://github.com/arkime/arkime/issues/1350
#   see https://github.com/arkime/arkime/issues/1352
RUN ( /usr/local/bin/maxmind-mmdb-download.sh -o $ARKIME_DIR/etc || true ) && \
    curl -s -S -L -o $ARKIME_DIR/etc/ipv4-address-space.csv "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv" && \
    curl -s -S -L -o $ARKIME_DIR/etc/oui.txt "https://www.wireshark.org/download/automated/data/manuf"

RUN groupadd --gid $DEFAULT_GID $PGROUP && \
    useradd -M --uid $DEFAULT_UID --gid $DEFAULT_GID --home $ARKIME_DIR $PUSER && \
      usermod -a -G tty $PUSER && \
    chmod 755 /usr/local/bin/*.sh && \
    ln -sfr /usr/local/bin/pcap_processor.py /usr/local/bin/pcap_arkime_processor.py && \
    ln -sfr /usr/local/bin/arkime_update_geo.sh $ARKIME_DIR/bin/arkime_update_geo.sh && \
    mv $ARKIME_DIR/etc/config.ini $ARKIME_DIR/etc/config.orig.ini && \
    cp $ARKIME_DIR/bin/capture $ARKIME_DIR/bin/capture-offline && \
    chown root:${PGROUP} $ARKIME_DIR/bin/capture && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' $ARKIME_DIR/bin/capture && \
    chown root:${PGROUP} /sbin/ethtool && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool && \
    mkdir -p /var/run/arkime $ARKIME_DIR/logs $ARKIME_DIR/lua && \
    chown -R $PUSER:$PGROUP $ARKIME_DIR/etc $ARKIME_DIR/lua $ARKIME_DIR/rules $ARKIME_DIR/logs /var/run/arkime
#Update Path
ENV PATH="/opt:$ARKIME_DIR/bin:${PATH}"

EXPOSE 8000 8005 8081
WORKDIR $ARKIME_DIR

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "arkime", \
            "/usr/local/bin/docker_entrypoint.sh"]

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
