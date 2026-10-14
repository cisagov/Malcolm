FROM ghcr.io/mmguero/qemu-live-iso@sha256:42421f6f12085a5d2215a76149334b1d1105cc422fe4591b30567c384ac80189

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://idaholab.github.io/Malcolm/docs/hedgehog-raspi-build.html'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/hedgehog-raspi'
LABEL org.opencontainers.image.description='Hedgehog Linux network sensor Raspberry Pi image wrapped in a Docker image'

ARG QEMU_CPU=4
ARG QEMU_RAM=4096
ENV QEMU_CPU $QEMU_CPU
ENV QEMU_RAM $QEMU_RAM

# just using the base to serve the .img for download, not actually run it in qemu
ENV NOVNC_START false
ENV QEMU_RESTART false
ENV QEMU_START false

ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} https://raw.githubusercontent.com/idaholab/Malcolm/main/docs/images/hedgehog/logo/favicon.ico /image/favicon.ico
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} raspi_*.* /image/

RUN ls /image/raspi_*.img.xz
