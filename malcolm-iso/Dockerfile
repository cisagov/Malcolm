FROM ghcr.io/mmguero/qemu-live-iso@sha256:42421f6f12085a5d2215a76149334b1d1105cc422fe4591b30567c384ac80189

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

ARG QEMU_CPU=4
ARG QEMU_RAM=4096
ARG IMAGE_NAME=malcolm
ENV QEMU_CPU $QEMU_CPU
ENV QEMU_RAM $QEMU_RAM
ENV IMAGE_NAME $IMAGE_NAME

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title="ghcr.io/idaholab/malcolm/${IMAGE_NAME}"
LABEL org.opencontainers.image.description="Malcolm network traffic analysis tool suite ISO (${IMAGE_NAME} flavor) in qemu"

ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} https://raw.githubusercontent.com/idaholab/Malcolm/main/docs/images/icon/favicon.ico /image/favicon.ico
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} ${IMAGE_NAME}-*.log /image/
ADD --chown=${DEFAULT_UID}:${DEFAULT_GID} ${IMAGE_NAME}-*.iso /image/live.iso
