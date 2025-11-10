# Base and setup configuration
#FROM ubuntu:24.04
FROM ubuntu:22.04

LABEL maintainer="malcolm@inl.gov"
# LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/strelka-backend'
LABEL org.opencontainers.image.description='Malcolm container providing Strelka backend'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "strelka"
ENV PGROUP "strelka"
ENV PUSER_PRIV_DROP true
USER root

# Environment variables
ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONFAULTHANDLER=1
ENV PYTHONUNBUFFERED=1

# User configuration
RUN mkdir -p /home/${PUSER} && \
    groupadd --gid ${DEFAULT_GID} ${PGROUP} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /home/${PUSER} ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    chown -R $PUSER:$PGROUP /home/${PUSER}

RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

ARG CONFIG_TESTS=false
ARG TINI_VERSION=0.19.0
ARG JOHN_VERSION=1.9.1-ce
ARG YARA_VERSION=4.3.1
ARG EXIFTOOL_VERSION=12.60
ARG SEVENZ_VERSION=2409

# Install build packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get -qq update && \
    apt-get install -qq -y --no-install-recommends \
        automake build-essential ca-certificates cmake curl gcc git dirmngr \
        gnupg gpg libbz2-dev libgmp-dev libglu1-mesa liblzma-dev libpcap-dev \
        libtool libgomp1 make ncat openssh-client swig pkg-config supervisor \
        yasm zlib1g-dev && \
    cpan -i Compress::Raw::Lzma

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get -qq update && \
    apt-get install -qq -y --no-install-recommends \
        libarchive-dev libfuzzy-dev libjansson-dev libmagic-dev libssl-dev

# Add tini to use as our init inside the container.
RUN curl -sSLf -o /usr/bin/tini \
        "https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini-$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')" && \
    chmod a+rx /usr/bin/tini

# Install JTR; this is -very, very slow to build- so do it -as early as
# possible- so we hopefully don't ever have to redo it. Ever. Please. The
# maintainer isn't big on releases or tags so grab an arbitrary, but consistent,
# commit. Additionally jump through some extra hoops to get the single commit to
# save some download time.
RUN mkdir -p /tmp/build-jtr && \
    cd /tmp/build-jtr && \
    curl -OL https://github.com/openwall/john-packages/archive/refs/tags/v$JOHN_VERSION.tar.gz && \
    tar -xf v$JOHN_VERSION.tar.gz && \
    JOHN_COMMIT=$(sed -rne 's/ *source-commit: *(.+)/\1/p' john-packages-$JOHN_VERSION/deploy/snap/snapcraft.yaml) && \
    [ -n "$JOHN_COMMIT" ] && \
    mkdir /jtr && \
    cd /jtr && \
    git init && \
    git remote add origin https://github.com/openwall/john.git && \
    git fetch --depth 1 origin $JOHN_COMMIT && \
    git reset --hard FETCH_HEAD && \
    rm -rf .git && \
    cd src && \
    ./configure && \
    make -s clean && \
    make -sj4 && \
    make install && \
    cp -Tr /jtr/run/ /jtr && \
    rm -rf /jtr/run && \
    chmod -R 777 /jtr && \
    chown -R $PUSER:$PGROUP /jtr

# Download and compile exiftool
RUN mkdir -p /tmp/build-exiftool && \
    cd /tmp/build-exiftool && \
    curl -OL https://github.com/exiftool/exiftool/archive/refs/tags/$EXIFTOOL_VERSION.tar.gz && \
    tar -xf $EXIFTOOL_VERSION.tar.gz && \
    cd exiftool-$EXIFTOOL_VERSION && \
    perl Makefile.PL && \
    make -s && \
    make -s install

# Download and move binary for 7z 24.09
RUN mkdir -p /tmp/install-7z && \
    cd /tmp/install-7z && \
    curl -fsSL -o 7z.tar.xz https://7-zip.org/a/7z${SEVENZ_VERSION}-linux-$(uname -m | sed 's/x86_64/x64/' | sed 's/aarch64/arm64/').tar.xz && \
    tar -xf 7z.tar.xz && \
    cp 7zz /usr/local/bin

# Install YARA
RUN mkdir -p /tmp/build-yara && \
    cd /tmp/build-yara && \
    curl -OL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz && \
    tar -xf v$YARA_VERSION.tar.gz && \
    cd yara-$YARA_VERSION && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-magic --enable-cuckoo && \
    make -s && \
    make -s install && \
    make -s check

RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
    python3-dev \
    python3-pip \
    python3-wheel \
    python3-setuptools \
    python3-venv \
    python-is-python3 \
    python3-setuptools

# Install yara-python
RUN mkdir -p /tmp/build-yara-python && \
    cd /tmp/build-yara-python && \
    curl -OL https://github.com/VirusTotal/yara-python/archive/v$YARA_VERSION.tar.gz && \
    tar -xf v$YARA_VERSION.tar.gz && \
    cd yara-python-$YARA_VERSION && \
    python3 setup.py build --dynamic-linking && \
    python3 setup.py install

#RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
#    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
#    apt-get -q update && \
#    apt-get install -q -y --no-install-recommends zeek-lts
#ENV PATH=$PATH:/opt/zeek/bin
##clean up zeek install
#    cp /opt/zeek/bin/zeek /bin/zeek && \
#    rm -rf /opt/zeek/share/btest /opt/zeek/bin && \
#    rm -rf /opt/zeek/lib/*.a && \

# Install runtime packages
RUN apt-get -q update && \
    apt-get install -q -y --no-install-recommends \
    antiword \
    bash \
    binwalk \
    libzbar0 \
    libgl1 \
    redis-server \
    rsync \
    tesseract-ocr \
    unrar \
    unzip \
    upx \
    jq

RUN apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/*

# Assign permissions to Strelka scan result logging directory
RUN mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/

USER $PUSER

RUN python3 -m venv /home/$PUSER/venv && \
    . /home/$PUSER/venv/bin/activate && \
    python3 -m pip install -U pip setuptools && \
    python3 -m pip install poetry ruamel.yaml rich-argparse semver && \
    poetry config virtualenvs.create false

# Set the working directory and copy the project files
WORKDIR /home/$PUSER/strelka/
ADD ./strelka/pyproject.toml \
    ./strelka/poetry.lock \
    ./

#./strelka/build/python/backend/oscrypto-1.3.0-version-regex-fix.patch

RUN . /home/$PUSER/venv/bin/activate && \
    poetry install --only main

#patch -Np1 \
#    -d $(dirname $(python3 -c 'import oscrypto as o; print(o.__file__)')) \
#    < oscrypto-1.3.0-version-regex-fix.patch

COPY ./strelka/src/python/ ./
RUN . /home/$PUSER/venv/bin/activate && \
    python3 setup.py -q build && \
    python3 setup.py -q install

USER root

#COPY ./strelka/build/python/backend/strelka-backend-entrypoint-venv-wrapper.sh /strelka-backend-entrypoint-venv-wrapper.sh
#COPY ./strelka/build/python/backend/strelka-backend-entrypoint.py /strelka-backend-entrypoint.py
#RUN chmod a+rx /strelka-backend-entrypoint-venv-wrapper.sh
#RUN chmod a+rx /strelka-backend-entrypoint.py
#COPY ./strelka/configs/python/backend/ /etc/strelka/
COPY ./filescan/strelka-configs/python/backend/ /etc/strelka/

## Run tests as non-root user
#USER $PUSER
#
## Run build checks
## Use --build-arg SCANNER_TEST=test_scan_<scannername>.py to ignore all but selected scanner
## ex: docker-compose build --build-arg SCANNER_TEST=test_scan_yara.py
#ARG SCANNER_TEST=""
#
## Run tests. Fail build if any tests fail.
#RUN echo '[+] Run build checks' && \
#    cd /strelka/strelka/ && \
#    if $SCANNER_TESTS; then python3 -m pytest -p no:cacheprovider -s tests/$SCANNER_TEST; fi && \
#    if $CONFIG_TESTS; then python3 -m pytest -s tests_configuration/; fi && \
#    echo '[+] Done'

USER root

# Remove build directories and unused files
RUN rm -rf /home/$PUSER/strelka/ && \
    rm -rf /root/.cache && \
    rm -rf /tmp/*

# Remove config directory (will bind mount once built)
RUN rm -rf /etc/strelka/

USER root

COPY --chmod=755 \
    shared/bin/docker-uid-gid-setup.sh \
    shared/bin/service_check_passthrough.sh \
    /usr/local/bin/

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "strelka"]

#    "/strelka-backend-entrypoint-venv-wrapper.sh", \
#    "/strelka-backend-entrypoint.py", \
#        "--username", "strelka", \
#        "--scanner-dir", "/strelka/plugins", \
#        "--manifest-dir", "/strelka/manifests", \
#        "--poetry", "/home/strelka/venv/bin/poetry", \
#        "--"]
#CMD ["/home/strelka/venv/bin/python", "-m", "strelka", \
#        "-c", "/etc/strelka/backend.yaml"]
# "-P", "/strelka/plugins", \
# "start"]
CMD ["/home/strelka/venv/bin/strelka-backend"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
