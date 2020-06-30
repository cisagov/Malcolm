FROM mmguero/elastalert:2.0.5

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/elastalert'
LABEL org.opencontainers.image.description='Malcolm container providing an alerting framework for Elasticsearch'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "node"
ENV PGROUP "node"

ENV TERM xterm

USER root

RUN apk update && \
    apk add bash curl && \
    rm -rf /var/cache/apk/*

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD elastalert/elastalert-start.sh /usr/local/bin/
ADD shared/bin/elastic_search_status.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/elastalert-start.sh && \
    mkdir -p /opt/elastalert/server_data/tests && \
    chown -R ${PUSER}:${PGROUP} /opt

VOLUME ["/opt/elastalert/server_data"]

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

USER ${PUSER}

CMD ["/usr/local/bin/elastalert-start.sh"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
