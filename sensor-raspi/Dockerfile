FROM ghcr.io/mmguero/qemu-live-iso:latest

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/sensor-iso/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='ghcr.io/cisagov/malcolm/hedgehog-raspi'
LABEL org.opencontainers.image.description='Hedgehog Linux network sensor Raspberry Pi image wrapped in a Docker image'

ARG QEMU_CPU=4
ARG QEMU_RAM=4096
ENV QEMU_CPU $QEMU_CPU
ENV QEMU_RAM $QEMU_RAM

# just using the base to serve the .img for download, not actually run it in qemu
ENV NOVNC_START false
ENV QEMU_RESTART false
ENV QEMU_START false

ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} https://raw.githubusercontent.com/cisagov/Malcolm/main/docs/images/hedgehog/logo/favicon.ico /image/favicon.ico
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} raspi_4_bookworm*.* /image/
