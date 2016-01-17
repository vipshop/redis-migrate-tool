MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS = -I $(top_srcdir)/src

AM_CFLAGS = -Wall -Wshadow
AM_CFLAGS += -Wno-unused-parameter -Wno-unused-value

noinst_LIBRARIES = libzipmap.a

noinst_HEADERS = zipmap.h

libzipmap_a_SOURCES =	\
	zipmap.c