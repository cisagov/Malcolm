FROM python:3-slim-bullseye as builder

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN    apt-get update -q \
    && apt-get install -y --no-install-recommends gcc \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip install flake8

COPY ./api /usr/src/app/
WORKDIR /usr/src/app

RUN python3 -m pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt \
    && flake8 --ignore=E501,F401

FROM python:3-slim-bullseye

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
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
ARG ARKIME_FIELDS_INDEX="arkime_fields"
ARG ARKIME_INDEX_PATTERN="arkime_sessions3-*"
ARG ARKIME_INDEX_TIME_FIELD="firstPacket"
ARG DASHBOARDS_URL="http://dashboards:5601/dashboards"
ARG OPENSEARCH_URL="http://opensearch:9200"
ARG RESULT_SET_LIMIT="500"

ENV HOME=/malcolm
ENV APP_HOME="${HOME}"/api
ENV APP_FOLDER="${APP_HOME}"
ENV FLASK_APP=project/__init__.py
ENV FLASK_ENV $FLASK_ENV
ENV ARKIME_FIELDS_INDEX $ARKIME_FIELDS_INDEX
ENV ARKIME_INDEX_PATTERN $ARKIME_INDEX_PATTERN
ENV ARKIME_INDEX_TIME_FIELD $ARKIME_INDEX_TIME_FIELD
ENV DASHBOARDS_URL $DASHBOARDS_URL
ENV OPENSEARCH_URL $OPENSEARCH_URL
ENV RESULT_SET_LIMIT $RESULT_SET_LIMIT

WORKDIR "${APP_HOME}"

COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /usr/src/app/requirements.txt .
COPY ./api "${APP_HOME}"
COPY shared/bin/opensearch_status.sh "${APP_HOME}"/

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
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
