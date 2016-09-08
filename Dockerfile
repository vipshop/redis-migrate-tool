FROM debian:jessie

COPY Makefile.am configure.ac /app/
COPY dep /app/dep
COPY src /app/src
RUN apt-get update && apt-get install -y --no-install-recommends python-pip automake libtool autoconf bzip2 make redis-tools 	\
	&& rm -rf /var/lib/apt/lists/* \
	&& cd /app && mkdir {m4,nodes,test} && autoreconf -fvi && ./configure && make \
	&& apt-get purge -yqq automake libtool autoconf bzip2 make \
    && apt-get autoremove -yqq \
    && apt-get clean

RUN pip install awscli	
EXPOSE 8888 
VOLUME /migrate
ADD entry-point.sh /
RUN chmod +x /entry-point.sh
CMD ["/entry-point.sh"]
