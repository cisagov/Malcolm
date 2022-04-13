FROM debian:11-slim as builder

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

ENV SURICATA_VER "6.0.0"
ENV SRCDIR "/src"
ENV SURICATADIR "/opt/suricata"

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        cargo \
        curl \
        libcap-ng-dev \
        libevent-dev \
        libgeoip-dev \
        libhiredis-dev \
        libhtp-dev \
        libhyperscan-dev \
        libjansson-dev \
        liblua5.1-dev \
        libluajit-5.1-dev \
        liblz4-dev \
        libmagic-dev \
        libmaxminddb-dev \
        libnet1-dev \
        libnetfilter-log-dev \
        libnetfilter-queue-dev \
        libnfnetlink-dev \
        libnss3-dev \
        libpcap-dev \
        libpcre3-dev \
        python3-pip \
        libtool \
        libyaml-dev \
        make \
        python3-yaml \
        zlib1g-dev \
        wget \
        zlib1g-dev && \
    ( curl https://sh.rustup.rs -sSf | bash -s -- -y ) && \
        echo 'source $HOME/.cargo/env' >> $HOME/.bashrc && \
    python3 -m pip install --no-cache-dir --upgrade pip && \
        python3 -m pip install --no-cache-dir suricata-update && \
    mkdir -p $SRCDIR/ $SURICATADIR/ && \
        wget https://www.openinfosecfoundation.org/download/suricata-$SURICATA_VER.tar.gz && \
        tar xvfz suricata-$SURICATA_VER.tar.gz --strip-components=1 -C $SRCDIR/ && \
        rm suricata-$SURICATA_VER.tar.gz && \
    cd $SRCDIR/ && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --mandir=/usr/share/man \
        --localstatedir=/var \
        --enable-non-bundled-htp \
        --enable-nfqueue \
        --enable-rust \
        --disable-gccmarch-native \
        --enable-hiredis \
        --enable-geoip \
        --enable-gccprotect \
        --enable-pie \
        --enable-luajit && \
    make && \
        make check && \
        make install DESTDIR="$SURICATADIR" && \
        make install-full DESTDIR="$SURICATADIR" && \
        ldconfig "$SURICATADIR"/usr/local/lib && \
        make install-conf DESTDIR="$SURICATADIR" && \
        make install-rules DESTDIR="$SURICATADIR" && \
    mkdir -p "$SURICATADIR"/usr/local/var/lib/suricata/ && \
        cp -r /usr/local/var/lib/suricata/rules "$SURICATADIR"/usr/local/var/lib/suricata/

FROM debian:11-slim

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/suricata'
LABEL org.opencontainers.image.description='Malcolm container providing Suricata'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "suricata"
ENV PGROUP "suricata"
ENV PUSER_PRIV_DROP true

ENV SUPERCRONIC_VERSION "0.1.12"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "048b95b48b708983effb2e5c935a1ef8483d9e3e"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

COPY --from=builder /target /

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        build-essential \
        curl \
        file \
        inotify-tools \
        libcap-ng0 \
        libevent-2.1-7 \
        libgeoip1 \
        libhiredis0.14 \
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
        procps \
        psmisc \
        python3-pip \
        python3-yaml \
        python3-zmq \
        supervisor \
        zlib1g && \
    python3 -m pip install --no-cache-dir --upgrade pip && \
        python3 -m pip install --no-cache-dir suricata-update && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
        echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
        chmod +x "$SUPERCRONIC" && \
        mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
        ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    ln -sfr /opt/pcap_processor.py /opt/pcap_suricata_processor.py && \
        (echo "*/5 * * * * /opt/eve-clean-logs.sh" > ${SUPERCRONIC_CRONTAB}) && \
    apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --chmod=755 shared/bin/pcap_processor.py /opt/
COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=644 shared/bin/pcap_utils.py /opt/
COPY --chmod=644 shared/pcaps/*.* /tmp/
COPY --chmod=644 suricata/supervisord.conf /etc/supervisord.conf
COPY --chmod=644 suricata/suricata.yaml /etc/suricata/suricata.yaml
COPY --chmod=755 suricata/scripts/eve-clean-logs.sh /opt/

ARG PCAP_PIPELINE_DEBUG=false
ARG PCAP_PIPELINE_DEBUG_EXTRA=false
ARG PCAP_MONITOR_HOST=pcap-monitor
#Whether or not to auto-tag logs based on filename
ARG AUTO_TAG=true
ARG SURICATA_AUTO_ANALYZE_PCAP_FILES=false
ARG SURICATA_AUTO_ANALYZE_PCAP_THREADS=1

ENV PCAP_PIPELINE_DEBUG $PCAP_PIPELINE_DEBUG
ENV AUTO_TAG $AUTO_TAG
ENV PCAP_PIPELINE_DEBUG_EXTRA $PCAP_PIPELINE_DEBUG_EXTRA
ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST
ENV SURICATA_AUTO_ANALYZE_PCAP_FILES $SURICATA_AUTO_ANALYZE_PCAP_FILES
ENV SURICATA_AUTO_ANALYZE_PCAP_THREADS $SURICATA_AUTO_ANALYZE_PCAP_THREADS

#Move Suricata YML

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]
