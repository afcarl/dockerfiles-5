FROM ubuntu
MAINTAINER Julien Bisconti <julien.bisconti@gmail.com>

RUN apt-get update && \
	apt-get install -y -q --no-install-recommends \
	software-properties-common \
	#curl \
	#wget \
	#autoconf \
	#automake \
	#bzip2 \
	#file \
	#g++ \
	#gcc \
	#imagemagick \
	#libbz2-dev \
	#libc6-dev \
	#libcurl4-openssl-dev \
	#libevent-dev \
	#libffi-dev \
	#libglib2.0-dev \
	#libjpeg-dev \
	#liblzma-dev \
	#libmagickcore-dev \
	#libmagickwand-dev \
	#libmysqlclient-dev \
	#libncurses-dev \
	#libpq-dev \
	#libreadline-dev \
	#libsqlite3-dev \
	#libssl-dev \
	#libtool \
	#libxml2-dev \
	#libxslt-dev \
	#libyaml-dev \
	#make \
	#patch \
	#xz-utils \
	#zlib1g-dev && \
	python python-pip libpq-dev python-dev python-lxml\
	libxml2-dev libxslt1-dev libmemcached-dev \
	&& rm -rf /var/lib/apt/lists/*

RUN add-apt-repository -y ppa:git-core/ppa && \
    apt-get update && \
    apt-get install -y -q --no-install-recommends git python python-pip

#WORKDIR /
RUN git clone https://github.com/mozilla/pontoon \
    && cd pontoon \
    && pip install -r requirements.txt \
    && ./bin/peep.py install -r requirements.txt

