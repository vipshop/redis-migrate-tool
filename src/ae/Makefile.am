MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS = -I $(top_srcdir)/src

AM_CFLAGS = -Wall -Wshadow
AM_CFLAGS += -Wno-unused-parameter -Wno-unused-value

noinst_LIBRARIES = libae.a

noinst_HEADERS = ae.h

libae_a_SOURCES =	\
	ae.c			\
	ae_epoll.c		\
	ae_evport.c		\
	ae_kqueue.c 	\
	ae_select.c