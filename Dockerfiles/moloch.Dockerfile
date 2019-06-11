FROM debian:stretch-slim

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

RUN sed -i "s/stretch main/stretch main contrib non-free/" /etc/apt/sources.list && \
    apt-get -q update && \
    bash -c "echo 'localepurge localepurge/nopurge multiselect en,en_US.UTF-8' | debconf-set-selections" && \
    apt-get install -q -y --no-install-recommends \
        bison \
        cgdb \
        cmake \
        cron \
        curl \
        ethtool \
        file \
        flex \
        g++ \
        gcc \
        gdb \
        geoip-bin \
        git \
        groff \
        groff-base \
        imagemagick \
        inotify-tools \
        libgoogle-perftools-dev \
        libgoogle-perftools4 \
        libjson-perl \
        libkrb5-3 \
        libkrb5-dev \
        libmaxminddb-dev \
        libmaxminddb0 \
        libpcap0.8 \
        libpcap0.8-dev \
        libssl1.0 \
        libssl1.0-dev \
        libtool \
        libwww-perl \
        libyaml-dev \
        localepurge \
        make \
        ninja-build \
        pandoc \
        patch \
        psmisc \
        python \
        python-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        rename \
        sudo \
        supervisor \
        swig \
        tshark \
        vim-tiny \
        wget \
        zlib1g-dev \
        tar gzip unzip cpio bzip2 lzma xz-utils p7zip-full unrar zlib1g && \
  dpkg-reconfigure localepurge && \
  localepurge && \
  pip3 install --no-cache-dir elasticsearch manuf geoip2 patool entrypoint2 pyunpack && \
  apt-get -q -y --purge remove python3-dev && \
  apt-get -q -y autoremove && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Declare args
ARG MOLOCH_VERSION=1.8.0
ARG ZEEK_VERSION=2.6.2
ARG CYBERCHEF_VERSION=8.30.1
ARG ES_HOST=elasticsearch
ARG ES_PORT=9200
ARG MALCOLM_USERNAME=admin
ARG MOLOCH_INTERFACE=eth0
ARG MOLOCH_ANALYZE_PCAP_THREADS=1
ARG CAPTURE=off
ARG WISE=off
ARG VIEWER=on
#Initalize is used to reset the environment from scratch and rebuild a new ES Stack
ARG INITIALIZEDB=false
#Wipe is the same as initalize except it keeps users intact
ARG WIPEDB=false
#Whether or not Moloch is in charge of deleting old PCAP files to reclaim space
ARG MANAGE_PCAP_FILES=false
#Whether or not to auto-tag logs based on filename
ARG AUTO_TAG=true
#Whether or not to run "bro -r XXXXX.pcap local" on each pcap file
ARG ZEEK_AUTO_ANALYZE_PCAP_FILES=false
ARG ZEEK_AUTO_ANALYZE_PCAP_THREADS=1
ARG ZEEK_EXTRACTOR_MODE=none
ARG ZEEK_EXTRACTOR_PATH=/data/zeek/extract_files

# Declare envs vars for each arg
ENV ES_HOST $ES_HOST
ENV ES_PORT $ES_PORT
ENV MOLOCH_LOCALELASTICSEARCH no
ENV MOLOCH_INET yes
ENV MOLOCH_ELASTICSEARCH "http://"$ES_HOST":"$ES_PORT
ENV MOLOCH_INTERFACE $MOLOCH_INTERFACE
ENV MALCOLM_USERNAME $MALCOLM_USERNAME
# this needs to be present, but is unused as nginx is going to handle auth for us
ENV MOLOCH_PASSWORD "ignored"
ENV MOLOCHDIR "/data/moloch"
ENV MOLOCHUSER "moloch"
ENV MOLOCH_ANALYZE_PCAP_THREADS $MOLOCH_ANALYZE_PCAP_THREADS
ENV CAPTURE $CAPTURE
ENV WISE $WISE
ENV VIEWER $VIEWER
ENV INITIALIZEDB $INITIALIZEDB
ENV WIPEDB $WIPEDB
ENV MANAGE_PCAP_FILES $MANAGE_PCAP_FILES
ENV AUTO_TAG $AUTO_TAG
ENV ZEEK_AUTO_ANALYZE_PCAP_FILES $ZEEK_AUTO_ANALYZE_PCAP_FILES
ENV ZEEK_AUTO_ANALYZE_PCAP_THREADS $ZEEK_AUTO_ANALYZE_PCAP_THREADS
ENV ZEEK_EXTRACTOR_MODE $ZEEK_EXTRACTOR_MODE
ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH

# we're now building moloch and bro source rather than installing the .deb
ADD moloch/patch/* /data/patches/
ADD README.md /data/moloch/doc/
ADD doc.css /data/moloch/doc/
ADD docs/images /data/moloch/doc/images/
ADD https://github.com/aol/moloch/archive/v$MOLOCH_VERSION.tar.gz /data/moloch.tar.gz
ADD https://github.com/gchq/CyberChef/releases/download/v$CYBERCHEF_VERSION/cyberchef.htm /data/moloch/doc/cyberchef.htm
ADD https://www.zeek.org/downloads/bro-$ZEEK_VERSION.tar.gz /data/bro.tar.gz
RUN apt-get -q update && \
    cd /data/moloch/doc/images && \
      find . -name "*.png" -exec bash -c 'convert "{}" -fuzz 2% -transparent white -background white -alpha remove -strip -interlace Plane -quality 85% "{}.jpg" && rename "s/\.png//" "{}.jpg"' \; && \
      cd /data/moloch/doc && \
      sed -i "s/^# Malcolm$//" README.md && \
      sed -i '/./,$!d' README.md && \
      sed -i "s/.png/.jpg/g" README.md && \
      sed -i "s@docs/images@images@g" README.md && \
      pandoc -s --self-contained --metadata title="Malcolm README" --css /data/moloch/doc/doc.css -o /data/moloch/doc/README.html /data/moloch/doc/README.md && \
    groupadd --gid 1000 $MOLOCHUSER && \
    useradd -M --uid 1000 --gid 1000 --home $MOLOCHDIR $MOLOCHUSER && \
    cd /data && \
    tar -xvf "bro.tar.gz" && \
      rm -f "bro.tar.gz" && \
      cd "./bro-"$ZEEK_VERSION && \
      ./configure --prefix=/usr --generator=Ninja && \
      cd build && \
      ninja && \
      ninja install && \
      strip --strip-unneeded \
        /usr/bin/bro \
        /usr/bin/bro-cut \
        /usr/bin/binpac \
        /usr/lib/libbroker.so.. \
        /usr/lib/libcaf_core.so.0.16.2 \
        /usr/lib/libcaf_io.so.0.16.2 \
        /usr/lib/libcaf_openssl.so.0.16.2 && \
    git clone --depth 1 https://github.com/salesforce/ja3 /tmp/ja3 && \
      mkdir -p /usr/share/bro/site/ja3 && \
      cp -v /tmp/ja3/bro/* /usr/share/bro/site/ja3 && \
      rm -rf /tmp/ja3 && \
    cd /data && \
    tar -xvf "moloch.tar.gz" && \
      rm -f "moloch.tar.gz" && \
      cd "./moloch-"$MOLOCH_VERSION && \
      bash -c 'for i in /data/patches/*; do patch -p1 < $i; done' && \
      cp -v /data/moloch/doc/images/moloch/moloch_155.png ./viewer/public/moloch_155.png && \
      cp -v /data/moloch/doc/images/moloch/moloch_77.png ./viewer/public/moloch_77.png && \
      cp -v /data/moloch/doc/images/moloch/header_logo.png ./parliament/vueapp/src/assets/header_logo.png && \
      cp -v /data/moloch/doc/images/moloch/header_logo.png ./viewer/public/header_logo.png && \
      cp -v /data/moloch/doc/images/moloch/header_logo.png ./viewer/vueapp/src/assets/logo.png && \
      find /data/moloch/doc/images/screenshots -name "*.png" -delete && \
      cp -v /data/moloch/doc/cyberchef.htm ./viewer/public/cyberchef.htm && \
      rm -f ./viewer/public/cyberchef.htm.gz && \
      gzip ./viewer/public/cyberchef.htm && \
      chmod 664 ./viewer/public/cyberchef.htm.gz /data/moloch/doc/cyberchef.htm && \
      export PATH="/data/moloch/bin:${PATH}" && \
      ln -sf /data/moloch/bin/npm /usr/local/bin/npm && \
      ln -sf /data/moloch/bin/node /usr/local/bin/node && \
      ln -sf /data/moloch/bin/npx /usr/local/bin/npx && \
      ./easybutton-build.sh --install && \
      npm cache clean --force && \
    apt-get -q -y remove --purge \
        autoconf \
        automake \
        autopoint \
        autotools-dev \
        bison \
        bsdmainutils \
        bzip2-doc \
        cmake \
        debhelper \
        dh-autoreconf \
        dh-strip-nondeterminism \
        dwz \
        flex \
        g++ \
        gcc \
        git \
        imagemagick \
        intltool-debian \
        libbison-dev \
        libbz2-dev \
        libffi-dev \
        libfl-dev \
        libgeoip-dev \
        libgoogle-perftools-dev \
        libkrb5-dev \
        libltdl-dev \
        libmagic-dev \
        libmaxminddb-dev \
        libncurses-dev \
        libpcap0.8-dev \
        libpcre3-dev \
        libpng-dev \
        libreadline-dev \
        libssl1.0-dev \
        m4 \
        make \
        man-db \
        ninja-build \
        pandoc \
        pkg-config \
        po-debconf \
        python-dev \
        rename \
        uuid-dev \
        zlib1g-dev && \
    apt-get -q -y autoremove && \
    apt-get clean && \
    rm -rf "/data/moloch-"$MOLOCH_VERSION "/data/bro-"$ZEEK_VERSION /var/lib/apt/lists/* /tmp/* /var/tmp/*

# add configuration and scripts
ADD moloch/scripts /data/
ADD moloch/etc /data/moloch/etc/
ADD https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv /data/moloch/etc/ipv4-address-space.csv
ADD https://raw.githubusercontent.com/wireshark/wireshark/master/manuf /data/moloch/etc/oui.txt
ADD https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-Country /tmp/GeoLite2-Country.mmdb.gz
ADD https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-ASN /tmp/GeoLite2-ASN.mmdb.gz
ADD moloch/wise/source.*.js /data/moloch/wiseService/
ADD moloch/supervisord.conf /etc/supervisord.conf
ADD moloch/zeek/*.bro /usr/share/bro/site/
RUN chmod 755 /data/*.sh && \
    cp -f /data/moloch_update_geo.sh /data/moloch/bin/moloch_update_geo.sh && \
    bash -c 'zcat /tmp/GeoLite2-Country.mmdb.gz > /data/moloch/etc/GeoLite2-Country.mmdb' && \
    rm -f /tmp/GeoLite2-Country.mmdb.gz && \
    bash -c 'zcat /tmp/GeoLite2-ASN.mmdb.gz > /data/moloch/etc/GeoLite2-ASN.mmdb' && \
    rm -f /tmp/GeoLite2-ASN.mmdb.gz && \
    sed -i "s/^\(MOLOCH_LOCALELASTICSEARCH=\).*/\1"$MOLOCH_LOCALELASTICSEARCH"/" /data/moloch/bin/Configure && \
    sed -i "s/^\(MOLOCH_INET=\).*/\1"$MOLOCH_INET"/" /data/moloch/bin/Configure && \
    chown -R 1000:1000 $MOLOCHDIR/logs && \
    chmod u+s $MOLOCHDIR/bin/moloch-capture && \
    bash -c 'echo -e "* * * * * su -c /data/moloch-parse-pcap-folder.sh $MOLOCHUSER >/dev/null 2>&1\n* * * * * su -c /data/moloch-parse-autozeek-folder.sh $MOLOCHUSER >/dev/null 2>&1" | crontab -'

#Update Path
ENV PATH="/data:/data/moloch/bin:${PATH}"

VOLUME ["/data/configured"]

EXPOSE 8000 8005 8081
WORKDIR /data/moloch

# ENTRYPOINT ["/data/startmoloch.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]
