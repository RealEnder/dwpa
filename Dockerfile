FROM php:7.2.30-apache-buster
RUN docker-php-ext-install mysqli

RUN apt-get update
RUN apt-get install -y build-essential cron git qt5-default libssl-dev zlib1g-dev libcurl4-openssl-dev supervisor

COPY misc/services.conf /etc/supervisor/conf.d

ADD --chown=1000:crontab misc/rkg.cron /var/spool/cron/crontabs/www-data
RUN /bin/bash -c 'chmod 0600 /var/spool/cron/crontabs/www-data'

RUN usermod -u 1000 www-data

WORKDIR /tools
RUN mkdir /tools/bin

RUN git clone https://github.com/routerkeygen/routerkeygenPC
WORKDIR /tools/routerkeygenPC/cli
RUN qmake
RUN make
RUN cp -v /tools/routerkeygenPC/cli/routerkeygen-cli /tools/bin

WORKDIR /tools
RUN git clone https://github.com/ZerBea/hcxtools
WORKDIR /tools/hcxtools
RUN make
RUN cp -v /tools/hcxtools/hcxpcaptool /tools/bin
WORKDIR /tools/bin

RUN rm -rf /tools/routerkeygenPC
RUN rm -rf /tools/hcxtools

CMD ["/usr/bin/supervisord"]