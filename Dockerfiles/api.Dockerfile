FROM python:3-slim-bullseye as builder

WORKDIR /usr/src/app

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY ./api /usr/src/app/

RUN    apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && python3 -m pip install --upgrade pip \
    && pip install flake8==4.0.1 \
    && flake8 --indent-size=2 --ignore=E501,F401 . \
    && python3 -m pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt

FROM python:3-slim-bullseye

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/api'
LABEL org.opencontainers.image.description='Malcolm container providing a REST API for some information about network traffic'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "yeflask"
ENV PGROUP "yeflask"
ENV PUSER_PRIV_DROP true

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ARG FLASK_ENV=production
ARG OPENSEARCH_URL="http://opensearch:9200"

ENV HOME=/malcolm
ENV APP_HOME="${HOME}"/api
ENV APP_FOLDER="${APP_HOME}"
ENV FLASK_APP=project/__init__.py
ENV FLASK_ENV $FLASK_ENV
ENV OPENSEARCH_URL $OPENSEARCH_URL

WORKDIR "${APP_HOME}"

COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /usr/src/app/requirements.txt .
COPY ./api "${APP_HOME}"
COPY shared/bin/opensearch_status.sh "${APP_HOME}"/

ADD https://raw.githubusercontent.com/mmguero/docker/master/shared/docker-uid-gid-setup.sh /usr/local/bin/docker-uid-gid-setup.sh
RUN    apt-get -q update \
    && apt-get -y -q --no-install-recommends install curl netcat \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip install --no-cache /wheels/* \
    && chmod 755 /usr/local/bin/docker-uid-gid-setup.sh \
    && groupadd --gid ${DEFAULT_GID} ${PGROUP} \
    &&   useradd -M --uid ${DEFAULT_UID} --gid ${DEFAULT_GID} --home "${HOME}" ${PUSER} \
    &&   chown -R ${PUSER}:${PGROUP} "${HOME}" \
    &&   usermod -a -G tty ${PUSER} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 5000

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh", "${APP_HOME}/entrypoint.sh"]

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
