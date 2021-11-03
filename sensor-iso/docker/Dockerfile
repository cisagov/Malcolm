FROM tianon/qemu:native

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/sensor-iso/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/hedgehog'
LABEL org.opencontainers.image.description='Hedgehog Linux network sensor live image in qemu'

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

# configure unprivileged user and runtime parameters
ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "hedgehog"
ENV PGROUP "hedgehog"

ARG QEMU_CPU=4
ARG QEMU_RAM=4096
ARG QEMU_CDROM="/hedgehog/hedgehog.iso"
ARG QEMU_NO_SSH=1
ARG QEMU_BOOT="order=d"
ARG QEMU_START="true"
ARG QEMU_RESTART="true"
ENV QEMU_CPU $QEMU_CPU
ENV QEMU_RAM $QEMU_RAM
ENV QEMU_CDROM $QEMU_CDROM
ENV QEMU_NO_SSH $QEMU_NO_SSH
ENV QEMU_BOOT $QEMU_BOOT
ENV QEMU_START $QEMU_START
ENV QEMU_RESTART $QEMU_RESTART

ARG HTTP_SERVER_PORT=8000
ENV HTTP_SERVER_PORT $HTTP_SERVER_PORT

RUN apt-get -q update && \
    apt-get install --no-install-recommends -y -q \
      procps \
      psmisc \
      python3-minimal \
      supervisor && \
    apt-get -y autoremove -qq && \
    apt-get clean && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    groupadd --gid ${DEFAULT_GID} ${PUSER} && \
      useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home /nonexistant ${PUSER} && \
      usermod -a -G tty ${PUSER} && \
    mkdir -p /hedgehog && \
      chown -R ${DEFAULT_UID}:${DEFAULT_GID} /hedgehog && \
      chmod 750 /hedgehog

ADD sensor-iso/docker/supervisord.conf /etc/supervisord.conf
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} sensor-iso/hedgehog-*.log /hedgehog/
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} sensor-iso/hedgehog-*.iso /hedgehog/hedgehog.iso
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} https://raw.githubusercontent.com/mmguero-dev/Malcolm/development/sensor-iso/docs/logo/favicon.ico /hedgehog/favicon.ico

EXPOSE $HTTP_SERVER_PORT

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]

