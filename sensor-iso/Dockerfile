FROM ghcr.io/mmguero/qemu-live-iso:latest

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/sensor-iso/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='malcolmnetsec/hedgehog'
LABEL org.opencontainers.image.description='Hedgehog Linux network sensor live image in qemu'

ARG QEMU_CPU=4
ARG QEMU_RAM=4096
ENV QEMU_CPU $QEMU_CPU
ENV QEMU_RAM $QEMU_RAM

ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} https://raw.githubusercontent.com/cisagov/Malcolm/main/sensor-iso/docs/logo/favicon.ico /image/favicon.ico
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} hedgehog-*.log /image/
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} hedgehog-*.iso /image/live.iso
