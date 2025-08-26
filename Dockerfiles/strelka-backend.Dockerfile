# Base and setup configuration
FROM ubuntu:24.04
# FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
LABEL maintainer="Target Brands, Inc. TTS-CFC-OpenSource@target.com"

# User configuration
ARG CONFIG_TESTS=false

ARG TINI_VERSION=0.19.0
ARG JOHN_VERSION=1.9.1-ce
ARG YARA_VERSION=4.3.1
ARG EXIFTOOL_VERSION=12.60

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONFAULTHANDLER=1
ENV PYTHONUNBUFFERED=1

# User configuration
ARG USERNAME=strelka
ARG USER_UID=1001
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID --create-home --shell /bin/bash $USERNAME

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

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
ADD https://github.com/krallin/tini/releases/download/v${TINI_VERSION}/tini-static /tini
RUN chmod a+rx /tini

# Install JTR; this is -very, very slow to build- so do it -as early as
# possible- so we hopefully don't ever have to redo it. Ever. Please. The
# maintainer isn't big on releases or tags so grab an arbitrary, but consistent,
# commit. Additionally jump through some extra hoops to get the single commit to
# save some download time.
RUN mkdir -p /tmp/build-jtr && \
    cd /tmp/build-jtr && \
    curl -OL https://github.com/openwall/john-packages/archive/refs/tags/v$JOHN_VERSION.tar.gz && \
    tar -xf v$JOHN_VERSION.tar.gz && \
    JOHN_COMMIT=$(sed -rne 's/ *source-commit: *(.+)/\1/p' \
            john-packages-$JOHN_VERSION/deploy/snap/snapcraft.yaml) && \
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
    chown -R $USER_UID:$USER_UID /jtr

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
    curl -OL https://7-zip.org/a/7z2409-linux-x64.tar.xz && \
    tar -xf 7z2409-linux-x64.tar.xz && \
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
    binwalk \
    libzbar0 \
    libgl1 \
    redis-server \
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

USER $USERNAME

RUN python3 -m venv /home/$USERNAME/venv

RUN . /home/$USERNAME/venv/bin/activate && \
    python3 -m pip install -U pip setuptools && \
    python3 -m pip install poetry ruamel.yaml rich-argparse semver && \
    poetry config virtualenvs.create false

# Set the working directory and copy the project files
WORKDIR /home/$USERNAME/strelka/
ADD ./strelka/pyproject.toml \
    ./strelka/poetry.lock \
    ./

#./strelka/build/python/backend/oscrypto-1.3.0-version-regex-fix.patch

RUN . /home/$USERNAME/venv/bin/activate && \
    poetry install --only main

#patch -Np1 \
#    -d $(dirname $(python3 -c 'import oscrypto as o; print(o.__file__)')) \
#    < oscrypto-1.3.0-version-regex-fix.patch

COPY ./strelka/src/python/ ./
RUN . /home/$USERNAME/venv/bin/activate && \
    python3 setup.py -q build && \
    python3 setup.py -q install

USER root

#COPY ./strelka/build/python/backend/strelka-backend-entrypoint-venv-wrapper.sh /strelka-backend-entrypoint-venv-wrapper.sh
#COPY ./strelka/build/python/backend/strelka-backend-entrypoint.py /strelka-backend-entrypoint.py
#RUN chmod a+rx /strelka-backend-entrypoint-venv-wrapper.sh
#RUN chmod a+rx /strelka-backend-entrypoint.py
COPY ./strelka/configs/python/backend/ /etc/strelka/

## Run tests as non-root user
#USER $USERNAME
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
RUN rm -rf /home/$USERNAME/strelka/ && \
    rm -rf /root/.cache && \
    rm -rf /tmp/*

# Remove config directory (will bind mount once built)
RUN rm -rf /etc/strelka/

USER root

ENTRYPOINT ["/tini", "--"]
#    "/strelka-backend-entrypoint-venv-wrapper.sh", \
#    "/strelka-backend-entrypoint.py", \
#        "--username", "strelka", \
#        "--scanner-dir", "/strelka/plugins", \
#        "--manifest-dir", "/strelka/manifests", \
#        "--poetry", "/home/strelka/venv/bin/poetry", \
#        "--"]
CMD ["/home/strelka/venv/bin/python", "-m", "strelka", \
        "-c", "/etc/strelka/backend.yaml"]
# "-P", "/strelka/plugins", \
# "start"]

