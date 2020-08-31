FROM debian:buster-slim AS build

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

ENV DEBIAN_FRONTEND noninteractive

ENV MOLOCH_VERSION "2.4.0"
ENV MOLOCHDIR "/data/moloch"
ENV MOLOCH_URL "https://codeload.github.com/aol/moloch/tar.gz/v${MOLOCH_VERSION}"
ENV MOLOCH_LOCALELASTICSEARCH no
ENV MOLOCH_INET yes

ADD moloch/scripts/bs4_remove_div.py /data/
ADD moloch/patch/* /data/patches/
ADD README.md $MOLOCHDIR/doc/
ADD doc.css $MOLOCHDIR/doc/
ADD docs/images $MOLOCHDIR/doc/images/

RUN sed -i "s/buster main/buster main contrib non-free/g" /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
        binutils \
        bison \
        cmake \
        curl \
        file \
        flex \
        g++ \
        gcc \
        gettext \
        git-core \
        groff \
        groff-base \
        imagemagick \
        libcap-dev \
        libjson-perl \
        libkrb5-dev \
        libmaxminddb-dev \
        libpcap0.8-dev \
        libssl-dev \
        libtool \
        libwww-perl \
        libyaml-dev \
        make \
        meson \
        ninja-build \
        pandoc \
        patch \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        rename \
        sudo \
        swig \
        wget \
        zlib1g-dev && \
  pip3 install --no-cache-dir beautifulsoup4 && \
  cd $MOLOCHDIR/doc/images && \
    find . -name "*.png" -exec bash -c 'convert "{}" -fuzz 2% -transparent white -background white -alpha remove -strip -interlace Plane -quality 85% "{}.jpg" && rename "s/\.png//" "{}.jpg"' \; && \
    cd $MOLOCHDIR/doc && \
    sed -i "s/^# Malcolm$//" README.md && \
    sed -i '/./,$!d' README.md && \
    sed -i "s/.png/.jpg/g" README.md && \
    sed -i "s@docs/images@images@g" README.md && \
    pandoc -s --self-contained --metadata title="Malcolm README" --css $MOLOCHDIR/doc/doc.css -o $MOLOCHDIR/doc/README.html $MOLOCHDIR/doc/README.md && \
  cd /data && \
    mkdir -p "./moloch-"$MOLOCH_VERSION && \
    curl -sSL "$MOLOCH_URL" | tar xzvf - -C "./moloch-"$MOLOCH_VERSION --strip-components 1 && \
    cd "./moloch-"$MOLOCH_VERSION && \
    bash -c 'for i in /data/patches/*; do patch -p 1 -r - --no-backup-if-mismatch < $i || true; done' && \
    cp -v $MOLOCHDIR/doc/images/moloch/moloch_155.png ./viewer/public/moloch_155.png && \
    cp -v $MOLOCHDIR/doc/images/moloch/moloch_77.png ./viewer/public/moloch_77.png && \
    cp -v $MOLOCHDIR/doc/images/moloch/header_logo.png ./parliament/vueapp/src/assets/header_logo.png && \
    cp -v $MOLOCHDIR/doc/images/moloch/header_logo.png ./viewer/public/header_logo.png && \
    find $MOLOCHDIR/doc/images/screenshots -name "*.png" -delete && \
    export PATH="$MOLOCHDIR/bin:${PATH}" && \
    ln -sfr $MOLOCHDIR/bin/npm /usr/local/bin/npm && \
    ln -sfr $MOLOCHDIR/bin/node /usr/local/bin/node && \
    ln -sfr $MOLOCHDIR/bin/npx /usr/local/bin/npx && \
    python3 /data/bs4_remove_div.py -i ./viewer/vueapp/src/components/users/Users.vue -o ./viewer/vueapp/src/components/users/Users.new -c "new-user-form" && \
    mv -vf ./viewer/vueapp/src/components/users/Users.new ./viewer/vueapp/src/components/users/Users.vue && \
    rm -rf ./viewer/vueapp/src/components/upload && \
    sed -i "s/^\(MOLOCH_LOCALELASTICSEARCH=\).*/\1"$MOLOCH_LOCALELASTICSEARCH"/" ./release/Configure && \
    sed -i "s/^\(MOLOCH_INET=\).*/\1"$MOLOCH_INET"/" ./release/Configure && \
    ./easybutton-build.sh --install && \
    npm cache clean --force && \
    bash -c "file ${MOLOCHDIR}/bin/* ${MOLOCHDIR}/node-v*/bin/* | grep 'ELF 64-bit' | sed 's/:.*//' | xargs -l -r strip -v --strip-unneeded"

FROM debian:buster-slim

LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/moloch'
LABEL org.opencontainers.image.description='Malcolm container providing Moloch'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "moloch"
ENV PGROUP "moloch"
ENV PUSER_PRIV_DROP true

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG ES_HOST=elasticsearch
ARG ES_PORT=9200
ARG MALCOLM_USERNAME=admin
ARG MOLOCH_INTERFACE=eth0
ARG MOLOCH_ANALYZE_PCAP_THREADS=1
ARG WISE=off
ARG VIEWER=on
#Whether or not Moloch is in charge of deleting old PCAP files to reclaim space
ARG MANAGE_PCAP_FILES=false
#Whether or not to auto-tag logs based on filename
ARG AUTO_TAG=true
ARG PCAP_PIPELINE_DEBUG=false
ARG PCAP_PIPELINE_DEBUG_EXTRA=false
ARG PCAP_MONITOR_HOST=pcap-monitor
ARG MAXMIND_GEOIP_DB_LICENSE_KEY=""

# Declare envs vars for each arg
ENV ES_HOST $ES_HOST
ENV ES_PORT $ES_PORT
ENV MOLOCH_ELASTICSEARCH "http://"$ES_HOST":"$ES_PORT
ENV MOLOCH_INTERFACE $MOLOCH_INTERFACE
ENV MALCOLM_USERNAME $MALCOLM_USERNAME
# this needs to be present, but is unused as nginx is going to handle auth for us
ENV MOLOCH_PASSWORD "ignored"
ENV MOLOCHDIR "/data/moloch"
ENV MOLOCH_ANALYZE_PCAP_THREADS $MOLOCH_ANALYZE_PCAP_THREADS
ENV WISE $WISE
ENV VIEWER $VIEWER
ENV MANAGE_PCAP_FILES $MANAGE_PCAP_FILES
ENV AUTO_TAG $AUTO_TAG
ENV PCAP_PIPELINE_DEBUG $PCAP_PIPELINE_DEBUG
ENV PCAP_PIPELINE_DEBUG_EXTRA $PCAP_PIPELINE_DEBUG_EXTRA
ENV PCAP_MONITOR_HOST $PCAP_MONITOR_HOST

COPY --from=build $MOLOCHDIR $MOLOCHDIR

RUN sed -i "s/buster main/buster main contrib non-free/" /etc/apt/sources.list && \
    apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
      curl \
      file \
      geoip-bin \
      gettext \
      libcap2-bin \
      libjson-perl \
      libkrb5-3 \
      libmaxminddb0 \
      libpcap0.8 \
      libssl1.0 \
      libtool \
      libwww-perl \
      libyaml-0-2 \
      libzmq5 \
      procps \
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
    pip3 install --no-cache-dir beautifulsoup4 pyzmq && \
    ln -sfr $MOLOCHDIR/bin/npm /usr/local/bin/npm && \
      ln -sfr $MOLOCHDIR/bin/node /usr/local/bin/node && \
      ln -sfr $MOLOCHDIR/bin/npx /usr/local/bin/npx && \
    apt-get -q -y --purge remove gcc gcc-8 cpp cpp-8 libssl-dev && \
      apt-get -q -y autoremove && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# add configuration and scripts
ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD moloch/scripts /data/
ADD shared/bin/pcap_moloch_and_zeek_processor.py /data/
ADD shared/bin/pcap_utils.py /data/
ADD shared/bin/elastic_search_status.sh /data/
ADD moloch/etc $MOLOCHDIR/etc/
ADD moloch/wise/source.*.js $MOLOCHDIR/wiseService/
ADD moloch/supervisord.conf /etc/supervisord.conf

# MaxMind now requires a (free) license key to download the free versions of
# their GeoIP databases. This should be provided as a build argument.
#   see https://dev.maxmind.com/geoip/geoipupdate/#Direct_Downloads
#   see https://github.com/aol/moloch/issues/1350
#   see https://github.com/aol/moloch/issues/1352
RUN [ ${#MAXMIND_GEOIP_DB_LICENSE_KEY} -gt 1 ] && for DB in ASN Country City; do \
      cd /tmp && \
      curl -s -S -L -o "GeoLite2-$DB.mmdb.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$DB&license_key=$MAXMIND_GEOIP_DB_LICENSE_KEY&suffix=tar.gz" && \
      tar xf "GeoLite2-$DB.mmdb.tar.gz" --wildcards --no-anchored '*.mmdb' --strip=1 && \
      mkdir -p $MOLOCHDIR/etc/ $MOLOCHDIR/logs/ && \
      mv -v "GeoLite2-$DB.mmdb" $MOLOCHDIR/etc/; \
      rm -f "GeoLite2-$DB*"; \
    done; \
  curl -s -S -L -o $MOLOCHDIR/etc/ipv4-address-space.csv "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv" && \
  curl -s -S -L -o $MOLOCHDIR/etc/oui.txt "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"

RUN groupadd --gid $DEFAULT_GID $PGROUP && \
    useradd -M --uid $DEFAULT_UID --gid $DEFAULT_GID --home $MOLOCHDIR $PUSER && \
      usermod -a -G tty $PUSER && \
    chmod 755 /data/*.sh && \
    ln -sfr /data/pcap_moloch_and_zeek_processor.py /data/pcap_moloch_processor.py && \
    cp -f /data/moloch_update_geo.sh $MOLOCHDIR/bin/moloch_update_geo.sh && \
    chmod u+s $MOLOCHDIR/bin/moloch-capture && \
    chown -R $PUSER:$PGROUP $MOLOCHDIR/logs && \
    mkdir -p /var/run/moloch && \
    chown -R $PUSER:$PGROUP /var/run/moloch

#Update Path
ENV PATH="/data:$MOLOCHDIR/bin:${PATH}"

EXPOSE 8000 8005 8081
WORKDIR $MOLOCHDIR

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
