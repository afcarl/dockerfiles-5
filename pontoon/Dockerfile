FROM ubuntu
MAINTAINER Julien Bisconti <julien.bisconti@gmail.com>

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends wget ca-certificates && \
    wget -O - http://apt.postgresql.org/pub/repos/apt/ACCC4CF8.asc | apt-key add -  && \
    echo 'deb http://apt.postgresql.org/pub/repos/apt/ trusty-pgdg main' > /etc/apt/sources.list.d/pgdg.list && \
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv E1DD270288B4E6030699E45FA1715D88E1DF1F24 && \
    echo "deb http://ppa.launchpad.net/git-core/ppa/ubuntu trusty main" >> /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    software-properties-common curl autoconf automake  \
    bzip2 file g++ gcc make patch xz-utils zlib1g-dev \
    git-core postgresql-client\ 
    imagemagick \
    libbz2-dev \
    libc6-dev \
    libcurl4-openssl-dev \
    libevent-dev \
    libffi-dev \
    libglib2.0-dev \
    libjpeg-dev \
    liblzma-dev \
    libmagickcore-dev \
    libmagickwand-dev \
    libmemcached-dev \
    libmysqlclient-dev \
    libncurses-dev \
    libpq-dev \
    libreadline-dev \
    libsqlite3-dev \
    libssl-dev \
    libtool \
    libxml2-dev \
    libxslt1-dev \
    libxslt-dev \
    libyaml-dev \
    python-pip python-dev python-lxml \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/tj/n.git /tmp/n &&  \
    cd /tmp/n && \
    make install && \
    n lts

RUN pip install --upgrade ndg-httpsclient virtualenv virtualenvwrapper \
    && cd / && git clone https://github.com/mozilla/pontoon \
    && cd pontoon \
    && virtualenv venv && source ./venv/bin/activate \
    && pip install -r requirements.txt
    

COPY entrypoint.sh /sbin/entrypoint.sh
RUN chmod 755 /sbin/entrypoint.sh

EXPOSE 8000/tcp
