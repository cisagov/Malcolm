FROM debian:bullseye-slim

# 2021 BYU MIM Capstone
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/suricata'
LABEL org.opencontainers.image.description='Malcolm container with IDS/IPS integration'

#Add Malcolm User Variables
ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000

ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "suricata"
ENV PGROUP "suricata"
ENV PUSER_PRIV_DROP true

#UPDATE VERSION OF SURICATA
ENV SURICATA_VER "6.0.0"
ENV SURICATADIR "/opt/suricata"

RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
        wget \
        curl \
        make \
        libpcre3 \
        libhtp-dev \
        libpcre3-dbg \
        libpcre3-dev \
        build-essential \
        autoconf \
        automake \
        libtool \
        libpcap-dev \
        libnet1-dev \
        libyaml-0-2 \
        libyaml-dev \
        zlib1g \
        zlib1g-dev \
        libmagic-dev \
        libcap-ng-dev \
        libjansson-dev \
        pkg-config cargo \
        libnetfilter-queue-dev \
        libcap-ng0 \
        libnss3-dev \
        libgeoip-dev \
        liblua5.1-dev \
        libhiredis-dev \
        libevent-dev \
        libluajit-5.1-dev \
        libmaxminddb-dev \
        libnetfilter-queue1 \
        libnetfilter-log-dev \
        libnetfilter-log1 \
        libnfnetlink-dev \
        libnfnetlink0 \
        python3-pip \
        supervisor \
        python3-zmq \
        procps \
        psmisc

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

ADD shared/bin/pcap_arkime_and_zeek_processor.py /opt/
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD shared/bin/pcap_utils.py /opt/
ADD shared/pcaps /tmp/
ADD suricata/supervisord.conf /etc/supervisord.conf
ADD suricata/rules/*.rules /var/lib/suricata/rules/
ADD suricata/suricata.yaml $SURICATADIR/suricata.yaml

#Setup User, Groups, and Configs
RUN addgroup --gid ${DEFAULT_GID} ${PUSER} && \
    useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
    usermod -a -G tty ${PUSER} && \
    chmod -R +rw $SURICATADIR && \
    ln -sfr /opt/pcap_arkime_and_zeek_processor.py /opt/pcap_suricata_processor.py

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
