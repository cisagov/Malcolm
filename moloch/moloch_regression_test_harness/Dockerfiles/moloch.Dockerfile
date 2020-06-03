FROM debian:buster-slim AS build

ENV DEBIAN_FRONTEND noninteractive

ENV GITHUB_URL "https://github.com/aol/moloch/"
ENV GITHUB_BRANCH "master"
ENV MOLOCHDIR "/data/moloch"
ENV MOLOCHUSER "moloch"

USER root

RUN apt-get -q update && \
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
        git \
        groff \
        groff-base \
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
        patch \
        python \
        python-dev \
        rename \
        sudo \
        swig \
        vim-tiny \
        wget \
        zlib1g-dev

RUN mkdir /data && \
    groupadd --gid 1000 $MOLOCHUSER && \
    useradd -M --uid 1000 --gid 1000 --home $MOLOCHDIR --no-create-home $MOLOCHUSER && \
    chown -R $MOLOCHUSER:$MOLOCHUSER /data && \
    usermod -aG sudo $MOLOCHUSER && \
    sed -i /etc/sudoers -re 's/^%sudo.*/%sudo ALL=(ALL:ALL) NOPASSWD: ALL/g' && \
    sed -i /etc/sudoers -re 's/^root.*/root ALL=(ALL:ALL) NOPASSWD: ALL/g'

USER $MOLOCHUSER

RUN git clone --recursive --depth=1 --single-branch -b "$GITHUB_BRANCH" "$GITHUB_URL" "$MOLOCHDIR" && \
    cd "$MOLOCHDIR" && \
    bash -c 'for i in /data/patches/*; do patch -p 1 -r - --no-backup-if-mismatch < $i || true; done' && \
    export PATH="$MOLOCHDIR/bin:$MOLOCHDIR/node-v10.21.0-linux-x64/bin:${PATH}" && \
    sudo ln -sfr $MOLOCHDIR/bin/npm /usr/local/bin/npm && \
    sudo ln -sfr $MOLOCHDIR/bin/node /usr/local/bin/node && \
    sudo ln -sfr $MOLOCHDIR/bin/npx /usr/local/bin/npx && \
    ./easybutton-build.sh && \
    (make check || true)

ENV PATH="/data:$MOLOCHDIR/bin:${PATH}"

EXPOSE 8000 8005 8081

WORKDIR $MOLOCHDIR/tests

CMD bash
