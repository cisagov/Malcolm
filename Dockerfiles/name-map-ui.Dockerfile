FROM nginx:alpine

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/name-map-ui'
LABEL org.opencontainers.image.description='Malcolm container providing a user interface for mapping names to network hosts and subnets'

ENV JQUERY_VERSION 1.6.4
ENV LISTJS_VERSION v1.5.0

ADD https://code.jquery.com/jquery-${JQUERY_VERSION}.min.js /tmp/jquery.min.js
ADD https://raw.githubusercontent.com/javve/list.js/${LISTJS_VERSION}/dist/list.min.js /tmp/list.min.js

RUN rm -rf /usr/share/nginx/html/* && \
    cd /usr/share/nginx/html && \
    mv /tmp/jquery.min.js /tmp/list.min.js ./ && \
    chmod 644 ./jquery.min.js ./list.min.js && \
    ln -s . name-map-ui

ADD name-map-ui/site/* /usr/share/nginx/html/
ADD docs/images/logo/Malcolm_banner.png /usr/share/nginx/html/
ADD docs/images/favicon/favicon.ico /usr/share/nginx/html/
ADD name-map-ui/nginx/sites-available/default /etc/nginx/sites-available/default

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
