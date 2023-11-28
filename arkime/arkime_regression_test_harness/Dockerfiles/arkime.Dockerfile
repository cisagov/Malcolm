FROM debian:buster-slim AS build

ENV DEBIAN_FRONTEND noninteractive

ENV GITHUB_URL "https://github.com/arkime/arkime/"
ENV GITHUB_BRANCH "master"
ENV ARKIME_DIR "/opt/arkime"
ENV ARKIME_USER "arkime"

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

RUN mkdir /opt && \
    groupadd --gid 1000 $ARKIME_USER && \
    useradd -M --uid 1000 --gid 1000 --home $ARKIME_DIR --no-create-home $ARKIME_USER && \
    chown -R $ARKIME_USER:$ARKIME_USER /opt && \
    usermod -aG sudo $ARKIME_USER && \
    sed -i /etc/sudoers -re 's/^%sudo.*/%sudo ALL=(ALL:ALL) NOPASSWD: ALL/g' && \
    sed -i /etc/sudoers -re 's/^root.*/root ALL=(ALL:ALL) NOPASSWD: ALL/g'

USER $ARKIME_USER

RUN git clone --recursive --depth=1 --single-branch -b "$GITHUB_BRANCH" "$GITHUB_URL" "$ARKIME_DIR" && \
    cd "$ARKIME_DIR" && \
    bash -c 'for i in /opt/patches/*; do patch -p 1 -r - --no-backup-if-mismatch < $i || true; done' && \
    export PATH="$ARKIME_DIR/bin:$ARKIME_DIR/node-v10.21.0-linux-x64/bin:${PATH}" && \
    sudo ln -sfr $ARKIME_DIR/bin/npm /usr/local/bin/npm && \
    sudo ln -sfr $ARKIME_DIR/bin/node /usr/local/bin/node && \
    sudo ln -sfr $ARKIME_DIR/bin/npx /usr/local/bin/npx && \
    ./easybutton-build.sh && \
    (make check || true) && \
    sudo npm -g install jison

ENV PATH="/opt:$ARKIME_DIR/bin:$ARKIME_DIR/node-v10.21.0-linux-x64/bin:${PATH}"

EXPOSE 8000 8005 8081

WORKDIR $ARKIME_DIR/tests

CMD bash
