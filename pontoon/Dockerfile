FROM dockerfile/python
MAINTAINER Julien Bisconti <julien.bisconti@gmail.com>


RUN apt-get update && \
    apt-get install -y -q --no-install-recommends software-properties-common && \
    add-apt-repository -y ppa:git-core/ppa && \
    apt-get update && \
    apt-get install -y -q --no-install-recommends git

# RUN     rm -rf /var/lib/apt/lists/*



VOLUME /app
WORKDIR /app

CMD ["tig"]
