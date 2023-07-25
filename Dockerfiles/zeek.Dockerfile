FROM debian:12-slim

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/zeek'
LABEL org.opencontainers.image.description='Malcolm container providing Zeek'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# configure unprivileged user and runtime parameters
ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "zeeker"
ENV PGROUP "zeeker"
# not dropping privileges globally: supervisord will take care of it
# for all processes, but first we need root to sure capabilities for
# traffic capturing tools are in-place before they are started.
# despite doing setcap here in the Dockerfile, the chown in
# docker-uid-gid-setup.sh will cause them to be lost, so we need
# a final check in docker_entrypoint.sh before startup
ENV PUSER_PRIV_DROP false
ENV PUSER_RLIMIT_UNLOCK true

# for download and install
ARG ZEEK_LTS=
ARG ZEEK_VERSION=5.2.2-0

ENV ZEEK_LTS $ZEEK_LTS
ENV ZEEK_VERSION $ZEEK_VERSION

ENV SUPERCRONIC_VERSION "0.2.26"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "7a79496cf8ad899b99a719355d4db27422396735"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

# for build
ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1

# put Zeek and Spicy in PATH
ENV ZEEK_DIR "/opt/zeek"
ENV PATH "${ZEEK_DIR}/bin:${PATH}"

# add script for building 3rd-party plugins
ADD shared/bin/zeek_install_plugins.sh /usr/local/bin/

# build and install system packages, zeek, spicy and plugins
RUN export DEBARCH=$(dpkg --print-architecture) && \
    apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
      bc \
      bison \
      ca-certificates \
      ccache \
      cmake \
      curl \
      ethtool \
      file \
      flex \
      g++ \
      gcc \
      git \
      gnupg2 \
      iproute2 \
      jq \
      less \
      libatomic1 \
      libcap2-bin \
      libfl-dev \
      libgoogle-perftools4 \
      libkrb5-3 \
      libmaxminddb-dev \
      libmaxminddb0 \
      libpcap-dev \
      libpcap0.8 \
      libssl-dev \
      libtcmalloc-minimal4 \
      libunwind8 \
      libzmq5 \
      locales-all \
      make \
      moreutils \
      ninja-build \
      procps \
      psmisc \
      python3 \
      python3-bs4 \
      python3-git \
      python3-pip \
      python3-semantic-version \
      python3-setuptools \
      python3-tz \
      python3-wheel \
      python3-zmq \
      rsync \
      supervisor \
      swig \
      tini \
      vim-tiny \
      zlib1g-dev && \
    python3 -m pip install --break-system-packages --no-cache-dir pymisp stix2 taxii2-client dateparser && \
    mkdir -p /tmp/zeek-packages && \
      cd /tmp/zeek-packages && \
      if [ -n "${ZEEK_LTS}" ]; then ZEEK_LTS="-lts"; fi && export ZEEK_LTS && \
      curl -sSL --remote-name-all \
        "https://download.zeek.org/binary-packages/Debian_12/amd64/libbroker${ZEEK_LTS}-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/amd64/zeek${ZEEK_LTS}-core-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/amd64/zeek${ZEEK_LTS}-core_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/amd64/zeek${ZEEK_LTS}-spicy-dev_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/amd64/zeek${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/amd64/zeekctl${ZEEK_LTS}_${ZEEK_VERSION}_amd64.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/all/zeek${ZEEK_LTS}-client_${ZEEK_VERSION}_all.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/all/zeek${ZEEK_LTS}-zkg_${ZEEK_VERSION}_all.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/all/zeek${ZEEK_LTS}-btest_${ZEEK_VERSION}_all.deb" \
        "https://download.zeek.org/binary-packages/Debian_12/all/zeek${ZEEK_LTS}-btest-data_${ZEEK_VERSION}_all.deb" && \
      dpkg -i ./*.deb && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    cd /tmp && \
    mkdir -p "${CCACHE_DIR}" && \
    zkg autoconfig --force && \
    bash /usr/local/bin/zeek_install_plugins.sh && \
    ( find "${ZEEK_DIR}"/lib "${ZEEK_DIR}"/var/lib/zkg \( -path "*/build/*" -o -path "*/CMakeFiles/*" \) -type f -name "*.*" -print0 | xargs -0 -I XXX bash -c 'file "XXX" | sed "s/^.*:[[:space:]]//" | grep -Pq "(ELF|gzip)" && rm -f "XXX"' || true ) && \
    ( find "${ZEEK_DIR}"/var/lib/zkg/clones -type d -name .git -execdir bash -c "pwd; du -sh; git pull --depth=1 --ff-only; git reflog expire --expire=all --all; git tag -l | xargs -r git tag -d; git gc --prune=all; du -sh" \; ) && \
    rm -rf "${ZEEK_DIR}"/var/lib/zkg/scratch && \
    rm -rf "${ZEEK_DIR}"/lib/zeek/python/zeekpkg/__pycache__ && \
    ( find "${ZEEK_DIR}/" -type f -exec file "{}" \; | grep -Pi "ELF 64-bit.*not stripped" | sed 's/:.*//' | xargs -l -r strip --strip-unneeded ) && \
    ( find "${ZEEK_DIR}"/lib/zeek/plugins/packages -type f -name "*.hlto" -exec chmod 755 "{}" \; || true ) && \
    mkdir -p "${ZEEK_DIR}"/share/zeek/site/intel/STIX && \
      mkdir -p "${ZEEK_DIR}"/share/zeek/site/intel/MISP && \
      touch "${ZEEK_DIR}"/share/zeek/site/intel/__load__.zeek && \
    cd /usr/lib/locale && \
      ( ls | grep -Piv "^(en|en_US|en_US\.utf-?8|C\.utf-?8)$" | xargs -l -r rm -rf ) && \
    cd /tmp && \
    apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/cache/*/*

# add configuration and scripts
COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD shared/bin/pcap_processor.py /usr/local/bin/
ADD shared/bin/pcap_utils.py /usr/local/bin/
ADD scripts/malcolm_utils.py /usr/local/bin/
ADD shared/bin/zeek*threat*.py ${ZEEK_DIR}/bin/
ADD shared/pcaps /tmp/pcaps
ADD zeek/supervisord.conf /etc/supervisord.conf
ADD zeek/config/*.zeek ${ZEEK_DIR}/share/zeek/site/
ADD zeek/config/*.txt ${ZEEK_DIR}/share/zeek/site/
ADD zeek/scripts/docker_entrypoint.sh /usr/local/bin/
ADD shared/bin/zeek_intel_setup.sh ${ZEEK_DIR}/bin/
ADD shared/bin/zeekdeploy.sh ${ZEEK_DIR}/bin/
ADD shared/bin/nic-capture-setup.sh /usr/local/bin/

# sanity checks to make sure the plugins installed and copied over correctly
# these ENVs should match the number of third party scripts/plugins installed by zeek_install_plugins.sh
ENV ZEEK_THIRD_PARTY_PLUGINS_COUNT 23
ENV ZEEK_THIRD_PARTY_PLUGINS_GREP  "(Zeek::Spicy|ANALYZER_SPICY_DHCP|ANALYZER_SPICY_DNS|ANALYZER_SPICY_HTTP|ANALYZER_SPICY_OSPF|ANALYZER_SPICY_OPENVPN_UDP\b|ANALYZER_SPICY_IPSEC_UDP\b|ANALYZER_SPICY_TFTP|ANALYZER_SPICY_WIREGUARD|ANALYZER_SPICY_LDAP_TCP|ANALYZER_SPICY_SYNCHROPHASOR_TCP|ANALYZER_SPICY_GENISYS_TCP|ANALYZER_S7COMM_TCP|Corelight::CommunityID|Corelight::PE_XOR|ICSNPP::BACnet|ICSNPP::BSAP|ICSNPP::ENIP|ICSNPP::ETHERCAT|ICSNPP::OPCUA_Binary|Salesforce::GQUIC|Zeek::PROFINET|Zeek::TDS)"
ENV ZEEK_THIRD_PARTY_SCRIPTS_COUNT 25
ENV ZEEK_THIRD_PARTY_SCRIPTS_GREP  "(bro-is-darknet/main|bro-simple-scan/scan|bzar/main|callstranger-detector/callstranger|cve-2020-0601/cve-2020-0601|cve-2020-13777/cve-2020-13777|CVE-2020-16898/CVE-2020-16898|CVE-2021-38647/omigod|CVE-2021-31166/detect|CVE-2021-41773/CVE_2021_41773|CVE-2021-42292/main|cve-2021-44228/CVE_2021_44228|cve-2022-22954/main|cve-2022-26809/main|CVE-2022-3602/__load__|hassh/hassh|http-more-files-names/main|ja3/ja3|pingback/detect|ripple20/ripple20|SIGRed/CVE-2020-1350|zeek-EternalSafety/main|zeek-httpattacks/main|zeek-sniffpass/__load__|zerologon/main)\.(zeek|bro)"

RUN mkdir -p /tmp/logs && \
    cd /tmp/logs && \
    "$ZEEK_DIR"/bin/zeek -NN local >zeeknn.log 2>/dev/null && \
      bash -c "(( $(grep -cP "$ZEEK_THIRD_PARTY_PLUGINS_GREP" zeeknn.log) >= $ZEEK_THIRD_PARTY_PLUGINS_COUNT)) && echo 'Zeek plugins loaded correctly' || (echo 'One or more Zeek plugins did not load correctly' && cat zeeknn.log && exit 1)" && \
    "$ZEEK_DIR"/bin/zeek -C -r /tmp/pcaps/udp.pcap local policy/misc/loaded-scripts 2>/dev/null && \
      bash -c "(( $(grep -cP "$ZEEK_THIRD_PARTY_SCRIPTS_GREP" loaded_scripts.log) == $ZEEK_THIRD_PARTY_SCRIPTS_COUNT)) && echo 'Zeek scripts loaded correctly' || (echo 'One or more Zeek scripts did not load correctly' && cat loaded_scripts.log && exit 1)" && \
    cd /tmp && \
    rm -rf /tmp/logs /tmp/pcaps

RUN groupadd --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
    usermod -a -G tty ${PUSER} && \
    chown root:${PGROUP} /sbin/ethtool "${ZEEK_DIR}"/bin/zeek "${ZEEK_DIR}"/bin/capstats && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ZEEK_DIR}"/bin/zeek && \
      setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ZEEK_DIR}"/bin/capstats && \
    touch "${SUPERCRONIC_CRONTAB}" && \
    chown -R ${DEFAULT_UID}:${DEFAULT_GID} "${ZEEK_DIR}"/share/zeek/site/intel "${SUPERCRONIC_CRONTAB}" && \
    ln -sfr /usr/local/bin/pcap_processor.py /usr/local/bin/pcap_zeek_processor.py && \
    ln -sfr /usr/local/bin/malcolm_utils.py "${ZEEK_DIR}"/bin/malcolm_utils.py

#Whether or not to auto-tag logs based on filename
ARG AUTO_TAG=true
#Whether or not to start up the pcap_processor script to monitor pcaps
ARG ZEEK_PCAP_PROCESSOR=true
#Whether or not to start up supercronic for updating intel definitions
ARG ZEEK_CRON=true
#Whether or not to run "zeek -r XXXXX.pcap local" on each pcap file
ARG ZEEK_AUTO_ANALYZE_PCAP_FILES=false
ARG ZEEK_AUTO_ANALYZE_PCAP_THREADS=1
ARG ZEEK_INTEL_ITEM_EXPIRATION=-1min
ARG ZEEK_INTEL_REFRESH_CRON_EXPRESSION=
ARG ZEEK_INTEL_REFRESH_THREADS=2
ARG ZEEK_INTEL_FEED_SINCE=
ARG ZEEK_EXTRACTOR_MODE=none
ARG ZEEK_EXTRACTOR_PATH=/zeek/extract_files
ARG PCAP_PIPELINE_VERBOSITY=""
ARG PCAP_MONITOR_HOST=pcap-monitor
ARG ZEEK_LIVE_CAPTURE=false
ARG ZEEK_ROTATED_PCAP=false
# PCAP_IFACE=comma-separated list of capture interfaces
ARG PCAP_IFACE=lo
ARG PCAP_IFACE_TWEAK=false
ARG PCAP_FILTER=

ENV AUTO_TAG $AUTO_TAG
ENV ZEEK_PCAP_PROCESSOR $ZEEK_PCAP_PROCESSOR
ENV ZEEK_CRON $ZEEK_CRON
ENV ZEEK_AUTO_ANALYZE_PCAP_FILES $ZEEK_AUTO_ANALYZE_PCAP_FILES
ENV ZEEK_AUTO_ANALYZE_PCAP_THREADS $ZEEK_AUTO_ANALYZE_PCAP_THREADS
ENV ZEEK_INTEL_ITEM_EXPIRATION $ZEEK_INTEL_ITEM_EXPIRATION
ENV ZEEK_INTEL_REFRESH_CRON_EXPRESSION $ZEEK_INTEL_REFRESH_CRON_EXPRESSION
ENV ZEEK_INTEL_REFRESH_THREADS $ZEEK_INTEL_REFRESH_THREADS
ENV ZEEK_INTEL_FEED_SINCE $ZEEK_INTEL_FEED_SINCE
ENV ZEEK_EXTRACTOR_MODE $ZEEK_EXTRACTOR_MODE
ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
ENV PCAP_PIPELINE_VERBOSITY $PCAP_PIPELINE_VERBOSITY
ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST
ENV ZEEK_LIVE_CAPTURE $ZEEK_LIVE_CAPTURE
ENV ZEEK_ROTATED_PCAP $ZEEK_ROTATED_PCAP
ENV PCAP_IFACE $PCAP_IFACE
ENV PCAP_IFACE_TWEAK $PCAP_IFACE_TWEAK
ENV PCAP_FILTER $PCAP_FILTER

# environment variables for zeek runtime tweaks (used in local.zeek)
ARG ZEEK_DISABLE_HASH_ALL_FILES=
ARG ZEEK_DISABLE_LOG_PASSWORDS=
ARG ZEEK_DISABLE_SSL_VALIDATE_CERTS=
ARG ZEEK_DISABLE_TRACK_ALL_ASSETS=
ARG ZEEK_DISABLE_BEST_GUESS_ICS=true
# TODO: assess spicy-analyzer that replace built-in Zeek parsers
# for now, disable them by default when a Zeek parser exists
ARG ZEEK_DISABLE_SPICY_DHCP=true
ARG ZEEK_DISABLE_SPICY_DNS=true
ARG ZEEK_DISABLE_SPICY_HTTP=true
ARG ZEEK_DISABLE_SPICY_IPSEC=
ARG ZEEK_DISABLE_SPICY_LDAP=
ARG ZEEK_DISABLE_SPICY_OPENVPN=
ARG ZEEK_DISABLE_SPICY_STUN=
ARG ZEEK_DISABLE_SPICY_TAILSCALE=
ARG ZEEK_DISABLE_SPICY_TFTP=
ARG ZEEK_DISABLE_SPICY_WIREGUARD=
ARG ZEEK_SYNCHROPHASOR_DETAILED=

ENV ZEEK_DISABLE_HASH_ALL_FILES $ZEEK_DISABLE_HASH_ALL_FILES
ENV ZEEK_DISABLE_LOG_PASSWORDS $ZEEK_DISABLE_LOG_PASSWORDS
ENV ZEEK_DISABLE_SSL_VALIDATE_CERTS $ZEEK_DISABLE_SSL_VALIDATE_CERTS
ENV ZEEK_DISABLE_TRACK_ALL_ASSETS $ZEEK_DISABLE_TRACK_ALL_ASSETS
ENV ZEEK_DISABLE_BEST_GUESS_ICS $ZEEK_DISABLE_BEST_GUESS_ICS

ENV ZEEK_DISABLE_SPICY_DHCP $ZEEK_DISABLE_SPICY_DHCP
ENV ZEEK_DISABLE_SPICY_DNS $ZEEK_DISABLE_SPICY_DNS
ENV ZEEK_DISABLE_SPICY_HTTP $ZEEK_DISABLE_SPICY_HTTP
ENV ZEEK_DISABLE_SPICY_IPSEC $ZEEK_DISABLE_SPICY_IPSEC
ENV ZEEK_DISABLE_SPICY_LDAP $ZEEK_DISABLE_SPICY_LDAP
ENV ZEEK_DISABLE_SPICY_OPENVPN $ZEEK_DISABLE_SPICY_OPENVPN
ENV ZEEK_DISABLE_SPICY_STUN $ZEEK_DISABLE_SPICY_STUN
ENV ZEEK_DISABLE_SPICY_TAILSCALE $ZEEK_DISABLE_SPICY_TAILSCALE
ENV ZEEK_DISABLE_SPICY_TFTP $ZEEK_DISABLE_SPICY_TFTP
ENV ZEEK_DISABLE_SPICY_WIREGUARD $ZEEK_DISABLE_SPICY_WIREGUARD
ENV ZEEK_SYNCHROPHASOR_DETAILED $ZEEK_SYNCHROPHASOR_DETAILED

ENV PUSER_CHOWN "$ZEEK_DIR"

VOLUME ["${ZEEK_DIR}/share/zeek/site/intel"]

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/docker_entrypoint.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "zeek"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
