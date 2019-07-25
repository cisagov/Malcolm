FROM debian:stretch-slim AS build

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

ENV MOLOCH_VERSION "1.8.0"
ENV MOLOCHDIR "/data/moloch"
ENV ZEEK_VERSION "2.6.2"
ENV ZEEK_DIR "/opt/bro"
ENV CYBERCHEF_VERSION "8.30.1"

ADD moloch/scripts/bs4_remove_div.py /data/
ADD moloch/patch/* /data/patches/
ADD README.md $MOLOCHDIR/doc/
ADD doc.css $MOLOCHDIR/doc/
ADD docs/images $MOLOCHDIR/doc/images/
ADD https://github.com/aol/moloch/archive/v$MOLOCH_VERSION.tar.gz /data/moloch.tar.gz
ADD https://github.com/gchq/CyberChef/releases/download/v$CYBERCHEF_VERSION/cyberchef.htm $MOLOCHDIR/doc/cyberchef.htm
ADD https://www.zeek.org/downloads/bro-$ZEEK_VERSION.tar.gz /data/bro.tar.gz

RUN sed -i "s/stretch main/stretch main contrib non-free/" /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
        bison \
        cmake \
        curl \
        flex \
        g++ \
        gcc \
        gettext \
        git \
        groff \
        groff-base \
        imagemagick \
        libcap-dev \
        libgoogle-perftools-dev \
        libjson-perl \
        libkrb5-dev \
        libmaxminddb-dev \
        libpcap0.8-dev \
        libssl1.0-dev \
        libtool \
        libwww-perl \
        libyaml-dev \
        make \
        ninja-build \
        pandoc \
        patch \
        python-dev \
        python3-dev \
        python3-pip \
        rename \
        sudo \
        swig \
        wget \
        zlib1g-dev && \
  pip3 install --no-cache-dir beautifulsoup4 && \
  cd /data && \
  tar -xvf "bro.tar.gz" && \
    rm -f "bro.tar.gz" && \
    cd "./bro-"$ZEEK_VERSION && \
    ./configure --prefix=$ZEEK_DIR --generator=Ninja && \
    cd build && \
    ninja && \
    ninja install && \
    strip --strip-unneeded \
      $ZEEK_DIR/bin/bro \
      $ZEEK_DIR/bin/bro-cut \
      $ZEEK_DIR/bin/binpac \
      $ZEEK_DIR/lib/libbroker.so.. \
      $ZEEK_DIR/lib/libcaf_core.so.0.16.2 \
      $ZEEK_DIR/lib/libcaf_io.so.0.16.2 \
      $ZEEK_DIR/lib/libcaf_openssl.so.0.16.2 && \
  git clone --depth 1 https://github.com/salesforce/ja3 /tmp/ja3 && \
    mkdir -p $ZEEK_DIR/share/bro/site/ja3 && \
    cp -v /tmp/ja3/bro/* $ZEEK_DIR/share/bro/site/ja3 && \
    rm -rf /tmp/ja3 && \
  cd $MOLOCHDIR/doc/images && \
    find . -name "*.png" -exec bash -c 'convert "{}" -fuzz 2% -transparent white -background white -alpha remove -strip -interlace Plane -quality 85% "{}.jpg" && rename "s/\.png//" "{}.jpg"' \; && \
    cd $MOLOCHDIR/doc && \
    sed -i "s/^# Malcolm$//" README.md && \
    sed -i '/./,$!d' README.md && \
    sed -i "s/.png/.jpg/g" README.md && \
    sed -i "s@docs/images@images@g" README.md && \
    pandoc -s --self-contained --metadata title="Malcolm README" --css $MOLOCHDIR/doc/doc.css -o $MOLOCHDIR/doc/README.html $MOLOCHDIR/doc/README.md && \
  cd /data && \
  tar -xvf "moloch.tar.gz" && \
    rm -f "moloch.tar.gz" && \
    cd "./moloch-"$MOLOCH_VERSION && \
    bash -c 'for i in /data/patches/*; do patch -p1 < $i; done' && \
    cp -v $MOLOCHDIR/doc/images/moloch/moloch_155.png ./viewer/public/moloch_155.png && \
    cp -v $MOLOCHDIR/doc/images/moloch/moloch_77.png ./viewer/public/moloch_77.png && \
    cp -v $MOLOCHDIR/doc/images/moloch/header_logo.png ./parliament/vueapp/src/assets/header_logo.png && \
    cp -v $MOLOCHDIR/doc/images/moloch/header_logo.png ./viewer/public/header_logo.png && \
    cp -v $MOLOCHDIR/doc/images/moloch/header_logo.png ./viewer/vueapp/src/assets/logo.png && \
    find $MOLOCHDIR/doc/images/screenshots -name "*.png" -delete && \
    cp -v $MOLOCHDIR/doc/cyberchef.htm ./viewer/public/cyberchef.htm && \
    rm -f ./viewer/public/cyberchef.htm.gz && \
    gzip ./viewer/public/cyberchef.htm && \
    chmod 664 ./viewer/public/cyberchef.htm.gz $MOLOCHDIR/doc/cyberchef.htm && \
    export PATH="$MOLOCHDIR/bin:${PATH}" && \
    ln -sf $MOLOCHDIR/bin/npm /usr/local/bin/npm && \
    ln -sf $MOLOCHDIR/bin/node /usr/local/bin/node && \
    ln -sf $MOLOCHDIR/bin/npx /usr/local/bin/npx && \
    python3 /data/bs4_remove_div.py -i ./viewer/vueapp/src/components/users/Users.vue -o ./viewer/vueapp/src/components/users/Users.new -c "new-user-form" && \
    mv -vf ./viewer/vueapp/src/components/users/Users.new ./viewer/vueapp/src/components/users/Users.vue && \
    ./easybutton-build.sh --install && \
    npm cache clean --force && \
  apt-get clean && \
  rm -rf $MOLOCHDIR"-"$MOLOCH_VERSION "/data/bro-"$ZEEK_VERSION /var/lib/apt/lists/* /tmp/* /var/tmp/*

FROM debian:stretch-slim AS runtime

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ENV DEBIAN_FRONTEND noninteractive

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
ENV ZEEK_DIR "/opt/bro"
ENV ZEEK_AUTO_ANALYZE_PCAP_FILES $ZEEK_AUTO_ANALYZE_PCAP_FILES
ENV ZEEK_AUTO_ANALYZE_PCAP_THREADS $ZEEK_AUTO_ANALYZE_PCAP_THREADS
ENV ZEEK_EXTRACTOR_MODE $ZEEK_EXTRACTOR_MODE
ENV ZEEK_EXTRACTOR_PATH $ZEEK_EXTRACTOR_PATH

COPY --from=build $MOLOCHDIR $MOLOCHDIR
COPY --from=build $ZEEK_DIR $ZEEK_DIR

RUN sed -i "s/stretch main/stretch main contrib non-free/" /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      cron \
      curl \
      file \
      geoip-bin \
      gettext \
      inotify-tools \
      libcap2-bin \
      libgoogle-perftools4 \
      libjson-perl \
      libkrb5-3 \
      libmaxminddb0 \
      libpcap0.8 \
      libssl1.0 \
      libtool \
      libwww-perl \
      libyaml-0-2 \
      psmisc \
      python \
      python3 \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      rename \
      sudo \
      supervisor \
      vim-tiny \
      wget \
      tar gzip unzip cpio bzip2 lzma xz-utils p7zip-full unrar zlib1g && \
    pip3 install --no-cache-dir beautifulsoup4 elasticsearch manuf geoip2 patool entrypoint2 pyunpack && \
    ln -sf $MOLOCHDIR/bin/npm /usr/local/bin/npm && \
      ln -sf $MOLOCHDIR/bin/node /usr/local/bin/node && \
      ln -sf $MOLOCHDIR/bin/npx /usr/local/bin/npx && \
    apt-get -q -y --purge remove gcc gcc-6 cpp cpp-6 libssl1.0-dev && \
    apt-get -q -y autoremove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# add configuration and scripts
ADD moloch/scripts /data/
ADD shared/bin/elastic_search_status.sh /data/
ADD shared/bin/cron_env_deb.sh /data/
ADD moloch/etc $MOLOCHDIR/etc/
ADD https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv $MOLOCHDIR/etc/ipv4-address-space.csv
ADD https://raw.githubusercontent.com/wireshark/wireshark/master/manuf $MOLOCHDIR/etc/oui.txt
ADD https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-Country /tmp/GeoLite2-Country.mmdb.gz
ADD https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-ASN /tmp/GeoLite2-ASN.mmdb.gz
ADD moloch/wise/source.*.js $MOLOCHDIR/wiseService/
ADD moloch/supervisord.conf /etc/supervisord.conf
ADD moloch/zeek/*.bro $ZEEK_DIR/share/bro/site/

RUN groupadd --gid 1000 $MOLOCHUSER && \
    useradd -M --uid 1000 --gid 1000 --home $MOLOCHDIR $MOLOCHUSER && \
    chmod 755 /data/*.sh && \
    cp -f /data/moloch_update_geo.sh $MOLOCHDIR/bin/moloch_update_geo.sh && \
    bash -c "zcat /tmp/GeoLite2-Country.mmdb.gz > $MOLOCHDIR/etc/GeoLite2-Country.mmdb" && \
    rm -f /tmp/GeoLite2-Country.mmdb.gz && \
    bash -c "zcat /tmp/GeoLite2-ASN.mmdb.gz > $MOLOCHDIR/etc/GeoLite2-ASN.mmdb" && \
    rm -f /tmp/GeoLite2-ASN.mmdb.gz && \
    sed -i "s/^\(MOLOCH_LOCALELASTICSEARCH=\).*/\1"$MOLOCH_LOCALELASTICSEARCH"/" $MOLOCHDIR/bin/Configure && \
    sed -i "s/^\(MOLOCH_INET=\).*/\1"$MOLOCH_INET"/" $MOLOCHDIR/bin/Configure && \
    chown -R 1000:1000 $MOLOCHDIR/logs && \
    chmod u+s $MOLOCHDIR/bin/moloch-capture && \
    bash -c 'echo -e "* * * * * su -c /data/moloch-parse-pcap-folder.sh $MOLOCHUSER >/dev/null 2>&1\n* * * * * su -c $MOLOCHDIR-parse-autozeek-folder.sh $MOLOCHUSER >/dev/null 2>&1" | crontab -'

#Update Path
ENV PATH="/data:$MOLOCHDIR/bin:$ZEEK_DIR/bin:${PATH}"

VOLUME ["/data/configured"]

EXPOSE 8000 8005 8081
WORKDIR $MOLOCHDIR

# ENTRYPOINT ["/data/startmoloch.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]
