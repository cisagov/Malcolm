FROM debian:buster-slim AS build

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

ENV DEBIAN_FRONTEND noninteractive

# build zeek and plugins (spicy, additional protocol parsers, etc.)

ENV CCACHE_DIR "/var/spool/ccache"
ENV CCACHE_COMPRESS 1
ENV SPICY_DIR "/opt/spicy"
ENV SRC_BASE_DIR "/usr/local/src"
ENV ZEEK_DIR "/opt/zeek"
ENV ZEEK_PATCH_DIR "${SRC_BASE_DIR}/zeek-patches"
ENV ZEEK_SRC_DIR "${SRC_BASE_DIR}/zeek-${ZEEK_VERSION}"
ENV ZEEK_VERSION "4.0.0"

ENV PATH "${ZEEK_DIR}/bin:${PATH}"

# empty for now...
# ADD zeek/patches ${ZEEK_PATCH_DIR}

RUN echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list && \
    echo "deb http://deb.debian.org/debian testing main" >> /etc/apt/sources.list && \
    echo "Package: bison,build-essential,cmake,python3,python3-dev,python3-pip,python3-setuptools,python3-wheel\\nPin: release a=testing\\nPin-Priority: 800\\n\\nPackage: *\\nPin: release a=stable\\nPin-Priority: 700\\n\\nPackage: *\\nPin: release a=buster-backports\\nPin-Priority: 650\\n\\n\\nPackage: *\\nPin: release a=testing\\nPin-Priority: 600\\n" > /etc/apt/preferences.d/pin && \
    echo 'APT::Default-Release "buster";' >> /etc/apt/apt.conf && \
      apt-get -q update && \
      apt-get install -q -y --no-install-recommends gnupg2 curl ca-certificates && \
    apt-get -q update && \
    apt-get install -q -y -t buster-backports --no-install-recommends \
        binutils \
        ccache \
        file \
        flex \
        git \
        google-perftools \
        jq \
        libfl-dev \
        libgoogle-perftools-dev \
        libkrb5-dev \
        libmaxminddb-dev \
        libpcap0.8-dev \
        libssl-dev \
        locales-all \
        make \
        ninja-build \
        patch \
        swig \
        zlib1g-dev && \
  apt-get install -q -y -t testing --no-install-recommends \
    bison \
    build-essential \
    cmake \
    python3 \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel && \
  pip3 install --no-cache-dir btest pre-commit GitPython semantic-version

RUN cd "${SRC_BASE_DIR}" && \
    curl -sSL "https://github.com/zeek/zeek/releases/download/v${ZEEK_VERSION}/zeek-${ZEEK_VERSION}.tar.gz" | tar xzf - -C "${SRC_BASE_DIR}" && \
      cd "./zeek-${ZEEK_VERSION}" && \
      bash -c "for i in ${ZEEK_PATCH_DIR}/* ; do patch -p 1 -r - --no-backup-if-mismatch < \$i || true; done" && \
      ./configure --prefix="${ZEEK_DIR}" --generator=Ninja --ccache --enable-perftools && \
      cd build && \
      ninja && \
      ninja install

RUN cd "${SRC_BASE_DIR}" && \
    git -c core.askpass=true clone --single-branch --recursive --shallow-submodules https://github.com/zeek/spicy "${SRC_BASE_DIR}"/spicy && \
      cd ./spicy && \
      ./configure --generator=Ninja --prefix="$SPICY_DIR" --with-zeek="$ZEEK_DIR" --enable-ccache && \
      ninja -j 2 -C build install

ADD shared/bin/zeek_install_plugins.sh /usr/local/bin/

RUN echo 'Y' | zkg autoconfig
# && \
#     bash /usr/local/bin/zeek_install_plugins.sh && \
# bash -c "find ${ZEEK_DIR}/lib -type d -name CMakeFiles -exec rm -rf '{}' \; 2>/dev/null || true" && \
# bash -c "file ${ZEEK_DIR}/{lib,bin}/* ${ZEEK_DIR}/lib/zeek/plugins/packages/*/lib/* ${ZEEK_DIR}/lib/zeek/plugins/*/lib/* ${SPICY_DIR}/{lib,bin}/* ${SPICY_DIR}/lib/spicy/Zeek_Spicy/lib/* | grep 'ELF 64-bit' | sed 's/:.*//' | xargs -l -r strip -v --strip-unneeded"

# FROM debian:buster-slim
#
# LABEL maintainer="malcolm.netsec@gmail.com"
# LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
# LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
# LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
# LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
# LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
# LABEL org.opencontainers.image.title='malcolmnetsec/zeek'
# LABEL org.opencontainers.image.description='Malcolm container providing Zeek'
#
# ARG DEFAULT_UID=1000
# ARG DEFAULT_GID=1000
# ENV DEFAULT_UID $DEFAULT_UID
# ENV DEFAULT_GID $DEFAULT_GID
# ENV PUSER "zeek"
# ENV PGROUP "zeek"
# ENV PUSER_PRIV_DROP true
#
# ENV DEBIAN_FRONTEND noninteractive
# ENV TERM xterm
#
# ENV ZEEK_DIR "/opt/zeek"
# ENV SPICY_DIR "/opt/spicy"
#
# COPY --from=build ${ZEEK_DIR} ${ZEEK_DIR}
# COPY --from=build ${SPICY_DIR} ${SPICY_DIR}
#
# RUN echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list && \
#     echo "deb http://deb.debian.org/debian testing main" >> /etc/apt/sources.list && \
#     echo "Package: bison,build-essential,cmake,python3,python3-dev,python3-pip,python3-setuptools,python3-wheel\\nPin: release a=testing\\nPin-Priority: 800\\n\\nPackage: *\\nPin: release a=stable\\nPin-Priority: 700\\n\\nPackage: *\\nPin: release a=buster-backports\\nPin-Priority: 650\\n\\n\\nPackage: *\\nPin: release a=testing\\nPin-Priority: 600\\n" > /etc/apt/preferences.d/pin && \
#     echo 'APT::Default-Release "buster";' >> /etc/apt/apt.conf && \
#       apt-get -q update && \
#       apt-get install -q -y --no-install-recommends gnupg2 curl ca-certificates && \
#     apt-get -q update && \
#     apt-get install -q -y -t buster-backports --no-install-recommends \
#       binutils \
#       file \
#       git \
#       libatomic1 \
#       libgoogle-perftools4 \
#       libkrb5-3 \
#       libmaxminddb0 \
#       libpcap0.8 \
#       libpcap0.8-dev \
#       libssl1.0 \
#       libtcmalloc-minimal4 \
#       libunwind8 \
#       libzmq5 \
#       procps \
#       psmisc \
#       python \
#       supervisor \
#       vim-tiny && \
#     apt-get install -q -y -t testing --no-install-recommends \
#       bison \
#       build-essential \
#       cmake \
#       python3 \
#       python3-pip \
#       python3-setuptools \
#       python3-wheel && \
#     pip3 install --no-cache-dir pyzmq && \
#     bash -c "( find /opt/zeek/ -type l ! -exec test -r {} \; -print | xargs -r -l rm -vf ) || true" && \
#     apt-get -q -y --purge remove libssl-dev && \
#       apt-get -q -y autoremove && \
#       apt-get clean && \
#       rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
#
# # add configuration and scripts
# ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
# ADD shared/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/
# ADD shared/bin/pcap_utils.py /usr/local/bin/
# ADD shared/pcaps /tmp/pcaps
# ADD zeek/supervisord.conf /etc/supervisord.conf
# ADD zeek/config/*.zeek ${ZEEK_DIR}/share/zeek/site/
#
# #Update Path
# ENV PATH "${ZEEK_DIR}/bin:${SPICY_DIR}/bin:${PATH}"
#
# # sanity check to make sure the plugins installed and copied over correctly
# # these ENVs should match the number of third party plugins installed by zeek_install_plugins.sh
# ENV ZEEK_THIRD_PARTY_PLUGINS_COUNT 27
# ENV ZEEK_THIRD_PARTY_GREP_STRING "(Bro_LDAP/scripts/main|bzar/main|callstranger|Corelight/PE_XOR/main|cve-2020-0601|CVE-2020-1350|cve-2020-13777|CVE-2020-16898|hassh/hassh|ja3/ja3|ripple20|Salesforce/GQUIC/main|spicy-noise|spicy/main|zeek-community-id/main|zeek-EternalSafety/main|zeek-httpattacks/main|ICSNPP_Bacnet/scripts/consts|ICSNPP_Bsap_ip/scripts/consts|ICSNPP_Bsap_serial/scripts/consts|ICSNPP_Enip/scripts/consts|zeek-plugin-profinet/main|zeek-plugin-s7comm/main|zeek-plugin-tds/main|zeek-sniffpass/main|Zeek_AF_Packet/scripts/init|zerologon/main)\.(zeek|bro)"
#
# RUN mkdir -p /tmp/logs && \
#     cd /tmp/logs && \
#       $ZEEK_DIR/bin/zeek -C -r /tmp/pcaps/udp.pcap local policy/misc/loaded-scripts 2>/dev/null && \
#       bash -c "(( $(grep -cP "$ZEEK_THIRD_PARTY_GREP_STRING" loaded_scripts.log) == $ZEEK_THIRD_PARTY_PLUGINS_COUNT)) && echo 'Zeek plugins loaded correctly' || (echo 'One or more Zeek plugins did not load correctly' && cat loaded_scripts.log && exit 1)" && \
#       cd /tmp && \
#       rm -rf /tmp/logs /tmp/pcaps
#
# #Whether or not to auto-tag logs based on filename
# ARG AUTO_TAG=true
# #Whether or not to run "zeek -r XXXXX.pcap local" on each pcap file
# ARG ZEEK_AUTO_ANALYZE_PCAP_FILES=false
# ARG ZEEK_AUTO_ANALYZE_PCAP_THREADS=1
# ARG ZEEK_EXTRACTOR_MODE=none
# ARG ZEEK_EXTRACTOR_PATH=/zeek/extract_files
# ARG PCAP_PIPELINE_DEBUG=false
# ARG PCAP_PIPELINE_DEBUG_EXTRA=false
# ARG PCAP_MONITOR_HOST=pcap-monitor
#
# ENV AUTO_TAG $AUTO_TAG
# ENV ZEEK_AUTO_ANALYZE_PCAP_FILES $ZEEK_AUTO_ANALYZE_PCAP_FILES
# ENV ZEEK_AUTO_ANALYZE_PCAP_THREADS $ZEEK_AUTO_ANALYZE_PCAP_THREADS
# ENV ZEEK_EXTRACTOR_MODE $ZEEK_EXTRACTOR_MODE
# ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH
# ENV PCAP_PIPELINE_DEBUG $PCAP_PIPELINE_DEBUG
# ENV PCAP_PIPELINE_DEBUG_EXTRA $PCAP_PIPELINE_DEBUG_EXTRA
# ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST
#
# # environment variables for zeek runtime tweaks (used in local.zeek)
# ARG ZEEK_DISABLE_MITRE_BZAR=
# ARG ZEEK_DISABLE_HASH_ALL_FILES=
# ARG ZEEK_DISABLE_LOG_PASSWORDS=
# ARG ZEEK_DISABLE_MQTT=
# ARG ZEEK_DISABLE_PE_XOR=
# ARG ZEEK_DISABLE_QUIC=
# ARG ZEEK_DISABLE_SSL_VALIDATE_CERTS=
# ARG ZEEK_DISABLE_TELNET=
# ARG ZEEK_DISABLE_TRACK_ALL_ASSETS=
# ARG ZEEK_DISABLE_WIREGUARD=
# ARG ZEEK_DISABLE_WIREGUARD_TRANSPORT_PACKETS=
#
# ENV ZEEK_DISABLE_MITRE_BZAR $ZEEK_DISABLE_MITRE_BZAR
# ENV ZEEK_DISABLE_HASH_ALL_FILES $ZEEK_DISABLE_HASH_ALL_FILES
# ENV ZEEK_DISABLE_LOG_PASSWORDS $ZEEK_DISABLE_LOG_PASSWORDS
# ENV ZEEK_DISABLE_MQTT $ZEEK_DISABLE_MQTT
# ENV ZEEK_DISABLE_PE_XOR $ZEEK_DISABLE_PE_XOR
# ENV ZEEK_DISABLE_QUIC $ZEEK_DISABLE_QUIC
# ENV ZEEK_DISABLE_SSL_VALIDATE_CERTS $ZEEK_DISABLE_SSL_VALIDATE_CERTS
# ENV ZEEK_DISABLE_TELNET $ZEEK_DISABLE_TELNET
# ENV ZEEK_DISABLE_TRACK_ALL_ASSETS $ZEEK_DISABLE_TRACK_ALL_ASSETS
# ENV ZEEK_DISABLE_WIREGUARD $ZEEK_DISABLE_WIREGUARD
# ENV ZEEK_DISABLE_WIREGUARD_TRANSPORT_PACKETS $ZEEK_DISABLE_WIREGUARD_TRANSPORT_PACKETS
#
# RUN groupadd --gid ${DEFAULT_GID} ${PUSER} && \
#     useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
#     usermod -a -G tty ${PUSER} && \
#     ln -sfr /usr/local/bin/pcap_moloch_and_zeek_processor.py /usr/local/bin/pcap_zeek_processor.py
#
# ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]
#
# CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]
#
#
# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
