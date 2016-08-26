FROM debian:jessie

COPY Makefile.am configure.ac /app/
COPY dep /app/dep
COPY src /app/src

RUN apt-get update && apt-get install -y automake libtool autoconf bzip2 make redis-tools 	\
	&& rm -rf /var/lib/apt/lists/* \
	&& cd /app && mkdir {m4,nodes,test} && autoreconf -fvi && ./configure && make \
	&& apt-get purge -yqq automake libtool autoconf bzip2 make \
    && apt-get autoremove -yqq \
    && apt-get clean
	
EXPOSE 8888 
VOLUME /migrate
CMD ["/app/src/redis-migrate-tool", "-c", "/migrate/rmt.conf"]
