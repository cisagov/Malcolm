FROM debian:12-slim

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/suricata'
LABEL org.opencontainers.image.description='Malcolm container providing Suricata'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# configure unprivileged user and runtime parameters
ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "suricata"
ENV PGROUP "suricata"
# not dropping privileges globally: supervisord will take care of it
# for all processes, but first we need root to sure capabilities for
# traffic capturing tools are in-place before they are started.
# despite doing setcap here in the Dockerfile, the chown in
# docker-uid-gid-setup.sh will cause them to be lost, so we need
# a final check in docker_entrypoint.sh before startup
ENV PUSER_PRIV_DROP false
ENV PUSER_RLIMIT_UNLOCK true

ENV SUPERCRONIC_VERSION "0.2.26"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "7a79496cf8ad899b99a719355d4db27422396735"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

ENV YQ_VERSION "4.33.3"
ENV YQ_URL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64"

ENV SURICATA_CONFIG_DIR /etc/suricata
ENV SURICATA_CONFIG_FILE "$SURICATA_CONFIG_DIR"/suricata.yaml
ENV SURICATA_CUSTOM_RULES_DIR /opt/suricata/rules
ENV SURICATA_LOG_DIR /var/log/suricata
ENV SURICATA_MANAGED_DIR /var/lib/suricata
ENV SURICATA_MANAGED_RULES_DIR "$SURICATA_MANAGED_DIR/rules"
ENV SURICATA_RUN_DIR /var/run/suricata
ENV SURICATA_UPDATE_CONFIG_FILE "$SURICATA_CONFIG_DIR"/update.yaml
ENV SURICATA_UPDATE_DIR "$SURICATA_MANAGED_DIR/update"
ENV SURICATA_UPDATE_SOURCES_DIR "$SURICATA_UPDATE_DIR/sources"
ENV SURICATA_UPDATE_CACHE_DIR "$SURICATA_UPDATE_DIR/cache"

RUN sed -i "s/main$/main contrib non-free/g" /etc/apt/sources.list.d/debian.sources && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        bc \
        curl \
        ethtool \
        file \
        inotify-tools \
        iproute2 \
        jq \
        less \
        libcap-ng0 \
        libcap2-bin \
        libevent-2.1-7 \
        libevent-pthreads-2.1-7 \
        libgeoip1 \
        libhiredis0.14 \
        libhtp2 \
        libhtp2 \
        libhyperscan5 \
        libjansson4 \
        liblua5.1-0 \
        libluajit-5.1-2 \
        liblz4-1 \
        libmagic1 \
        libmaxminddb0 \
        libnet1 \
        libnetfilter-log1 \
        libnetfilter-queue1 \
        libnfnetlink0 \
        libnss3 \
        libpcap0.8 \
        libpcre3 \
        libyaml-0-2 \
        moreutils \
        procps \
        psmisc \
        python3-pip \
        python3-ruamel.yaml \
        python3-setuptools \
        python3-wheel \
        python3-zmq \
        rsync \
        supervisor \
        suricata \
        suricata-update \
        tini \
        vim-tiny \
        zlib1g && \
    python3 -m pip install --break-system-packages --no-cache-dir watchdog && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
        echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
        chmod +x "$SUPERCRONIC" && \
        mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
        ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    curl -fsSL -o /usr/bin/yq "${YQ_URL}" && \
        chmod 755 /usr/bin/yq && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    ln -sfr /usr/local/bin/pcap_processor.py /usr/local/bin/pcap_suricata_processor.py && \
        (echo "*/5 * * * * /usr/local/bin/eve-clean-logs.sh\n0 */6 * * * /bin/bash /usr/local/bin/suricata-update-rules.sh\n" > ${SUPERCRONIC_CRONTAB}) && \
    mkdir -p "$SURICATA_CUSTOM_RULES_DIR" && \
        chown -R ${PUSER}:${PGROUP} "$SURICATA_CUSTOM_RULES_DIR" && \
    cp "$(dpkg -L suricata-update | grep 'update\.yaml$' | head -n 1)" \
        "$SURICATA_UPDATE_CONFIG_FILE" && \
    suricata-update update-sources --verbose --data-dir "$SURICATA_MANAGED_DIR" --config "$SURICATA_UPDATE_CONFIG_FILE" --suricata-conf "$SURICATA_CONFIG_FILE" && \
    suricata-update update --fail --verbose --etopen --data-dir "$SURICATA_MANAGED_DIR" --config "$SURICATA_UPDATE_CONFIG_FILE" --suricata-conf "$SURICATA_CONFIG_FILE" && \
    chown root:${PGROUP} /sbin/ethtool /usr/bin/suricata && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /usr/bin/suricata && \
    apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --chmod=644 shared/bin/pcap_utils.py /usr/local/bin/
COPY --chmod=644 suricata/supervisord.conf /etc/supervisord.conf
COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
COPY --chmod=755 shared/bin/nic-capture-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/pcap_processor.py /usr/local/bin/
COPY --chmod=644 scripts/malcolm_utils.py /usr/local/bin/
COPY --chmod=755 shared/bin/suricata_config_populate.py /usr/local/bin/
COPY --chmod=755 suricata/scripts/docker_entrypoint.sh /usr/local/bin/
COPY --chmod=755 suricata/scripts/eve-clean-logs.sh /usr/local/bin/
COPY --chmod=755 suricata/scripts/suricata-update-rules.sh /usr/local/bin/

ARG PCAP_PIPELINE_VERBOSITY=""
ARG PCAP_MONITOR_HOST=pcap-monitor
ARG AUTO_TAG=true
ARG SURICATA_PCAP_PROCESSOR=true
ARG SURICATA_CRON=true
ARG SURICATA_AUTO_ANALYZE_PCAP_FILES=false
ARG SURICATA_CUSTOM_RULES_ONLY=false
ARG SURICATA_AUTO_ANALYZE_PCAP_THREADS=1
ARG LOG_CLEANUP_MINUTES=30
ARG SURICATA_UPDATE_RULES=false
ARG SURICATA_UPDATE_DEBUG=false
ARG SURICATA_UPDATE_ETOPEN=true
ARG SURICATA_LIVE_CAPTURE=false
ARG SURICATA_ROTATED_PCAP=false
# PCAP_IFACE=comma-separated list of capture interfaces
ARG PCAP_IFACE=lo
ARG PCAP_IFACE_TWEAK=false
ARG PCAP_FILTER=

ENV PCAP_PIPELINE_VERBOSITY $PCAP_PIPELINE_VERBOSITY
ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST
ENV AUTO_TAG $AUTO_TAG
ENV SURICATA_PCAP_PROCESSOR $SURICATA_PCAP_PROCESSOR
ENV SURICATA_CRON $SURICATA_CRON
ENV SURICATA_AUTO_ANALYZE_PCAP_FILES $SURICATA_AUTO_ANALYZE_PCAP_FILES
ENV SURICATA_AUTO_ANALYZE_PCAP_THREADS $SURICATA_AUTO_ANALYZE_PCAP_THREADS
ENV SURICATA_CUSTOM_RULES_ONLY $SURICATA_CUSTOM_RULES_ONLY
ENV LOG_CLEANUP_MINUTES $LOG_CLEANUP_MINUTES
ENV SURICATA_UPDATE_RULES $SURICATA_UPDATE_RULES
ENV SURICATA_UPDATE_DEBUG $SURICATA_UPDATE_DEBUG
ENV SURICATA_UPDATE_ETOPEN $SURICATA_UPDATE_ETOPEN
ENV SURICATA_LIVE_CAPTURE $SURICATA_LIVE_CAPTURE
ENV SURICATA_ROTATED_PCAP $SURICATA_ROTATED_PCAP
ENV PCAP_IFACE $PCAP_IFACE
ENV PCAP_IFACE_TWEAK $PCAP_IFACE_TWEAK
ENV PCAP_FILTER $PCAP_FILTER

ENV PUSER_CHOWN "$SURICATA_CONFIG_DIR;$SURICATA_MANAGED_DIR;$SURICATA_LOG_DIR;$SURICATA_RUN_DIR"

VOLUME ["$SURICATA_CONFIG_DIR"]
VOLUME ["$SURICATA_CUSTOM_RULES_DIR"]
VOLUME ["$SURICATA_LOG_DIR"]
VOLUME ["$SURICATA_MANAGED_DIR"]
VOLUME ["$SURICATA_RUN_DIR"]

WORKDIR $SURICATA_RUN_DIR

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "suricata", \
            "/usr/local/bin/docker_entrypoint.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]
