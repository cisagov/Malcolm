FROM debian:11-slim

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

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

ENV SURICATA_VER "6.0.0"
ENV SURICATADIR "/opt/suricata"

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get install -q -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        bzip2 \
        cpio \
        curl \
        file \
        gzip \
        inotify-tools \
        libcap-ng-dev \
        libcap-ng0 \
        libevent-dev \
        libgeoip-dev \
        libhiredis-dev \
        libhtp-dev \
        libjansson-dev \
        liblua5.1-dev \
        libluajit-5.1-dev \
        libmagic-dev \
        libmaxminddb-dev \
        libnet1-dev \
        libnetfilter-log-dev \
        libnetfilter-log1 \
        libnetfilter-queue-dev \
        libnetfilter-queue1 \
        libnfnetlink-dev \
        libnfnetlink0 \
        libnss3-dev \
        libpcap-dev \
        libpcre3 \
        libpcre3-dbg \
        libpcre3-dev \
        libtool \
        libyaml-0-2 \
        libyaml-dev \
        lzma \
        make \
        p7zip \
        pkg-config cargo \
        procps \
        psmisc \
        python3-pip \
        python3-setuptools \
        python3-zmq \
        supervisor \
        tar \
        unar \
        unar \
        unzip \
        wget \
        zlib1g \
        zlib1g-dev

#Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

#Upgrade pip
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir suricata-update && \
    pip3 install pyyaml

#Build Suricata
RUN mkdir -p $SURICATADIR/ && \
    wget https://www.openinfosecfoundation.org/download/suricata-$SURICATA_VER.tar.gz && \
    tar xvfz suricata-$SURICATA_VER.tar.gz --strip-components=1 -C $SURICATADIR/ && \
    rm suricata-$SURICATA_VER.tar.gz && \
    cd $SURICATADIR/ && \
    ./configure \
    --prefix=/usr \
	--sysconfdir=/opt \
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
    make install && \
    make install-full

#Install SuperCronic
RUN curl -fsSLO "$SUPERCRONIC_URL" && \
    echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
    chmod +x "$SUPERCRONIC" && \
    mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
    ln -s "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic

ADD shared/bin/pcap_arkime_and_zeek_processor.py /opt/
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/pcap_utils.py /opt/
ADD shared/pcaps /tmp/
ADD suricata/supervisord.conf /etc/supervisord.conf
ADD suricata/rules/*.rules /var/lib/suricata/rules/
ADD suricata/suricata.yaml $SURICATADIR/suricata.yaml
ADD suricata/scripts/*.sh /opt/

#Setup User, Groups, and Configs
RUN addgroup --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
    usermod -a -G tty ${PUSER} && \
    chmod -R +rw $SURICATADIR && \
    ln -sfr /opt/pcap_arkime_and_zeek_processor.py /opt/pcap_suricata_processor.py && \
    chmod 755 /opt/*.sh && \
    (echo "*/5 * * * * /opt/eve-clean-logs.sh" > ${SUPERCRONIC_CRONTAB})

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
