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
    && flake8 --ignore=E501,F401 . \
    && python3 -m pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt

FROM python:3-slim-bullseye

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
