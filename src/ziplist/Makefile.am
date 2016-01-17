MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS = -I $(top_srcdir)/src

AM_CFLAGS = -Wall -Wshadow
AM_CFLAGS += -Wno-unused-parameter -Wno-unused-value

noinst_LIBRARIES = libziplist.a

noinst_HEADERS = ziplist.h

libziplist_a_SOURCES =	\
	ziplist.c