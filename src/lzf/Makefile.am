MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS = -I $(top_srcdir)/src

AM_CFLAGS = -Wall -Wshadow
AM_CFLAGS += -Wno-unused-parameter -Wno-unused-value

noinst_LIBRARIES = liblzf.a

noinst_HEADERS = lzf.h lzfP.h

liblzf_a_SOURCES =	\
	lzf_c.c			\
	lzf_d.c