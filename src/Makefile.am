MAINTAINERCLEANFILES = Makefile.in

AM_CPPFLAGS =
if !OS_SOLARIS
AM_CPPFLAGS += -D_GNU_SOURCE
endif
AM_CPPFLAGS += -I $(top_srcdir)/src/ae
AM_CPPFLAGS += -I $(top_srcdir)/src/lzf
AM_CPPFLAGS += -I $(top_srcdir)/src/intset
AM_CPPFLAGS += -I $(top_srcdir)/src/ziplist
AM_CPPFLAGS += -I $(top_srcdir)/src/zipmap
AM_CPPFLAGS += -I $(top_srcdir)/dep/jemalloc-4.0.4/include

AM_CFLAGS = 
AM_CFLAGS += -fno-strict-aliasing
AM_CFLAGS += -Wall -Wshadow
AM_CFLAGS += -Wpointer-arith
AM_CFLAGS += -Winline
AM_CFLAGS += -Wunused-function -Wunused-variable -Wunused-value
AM_CFLAGS += -Wno-unused-parameter -Wno-unused-value
AM_CFLAGS += -Wconversion -Wsign-compare
AM_CFLAGS += -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Wmissing-declarations

AM_LDFLAGS =
AM_LDFLAGS += -lm -lpthread -rdynamic
if OS_SOLARIS
AM_LDFLAGS += -lnsl -lsocket
endif

SUBDIRS = ae lzf intset ziplist zipmap

sbin_PROGRAMS = redis-migrate-tool

redis_migrate_tool_SOURCES =			\	 
	rmt_core.c rmt_core.h	\
	rmt_command.c rmt_command.h	\
	rmt_log.c rmt_log.h	\
	rmt_option.c rmt_option.h	\
	rmt_conf.c rmt_conf.h	\
	rmt_util.c rmt_util.h	\
	rmt_net.c rmt_net.h	\
	rmt_mttlist.c rmt_mttlist.h	\
	rmt_locklist.c rmt_locklist.h	\
	rmt_redis.c rmt_redis.h	\
	rmt_mbuf.c rmt_mbuf.h	\
	rmt_array.c rmt_array.h	\
	rmt_sds.c rmt_sds.h	\
	rmt_dict.c rmt_dict.h	\
	rmt_message.c rmt_message.h	\
	rmt_list.c rmt_list.h	\
	rmt_hash.c rmt_hash.h	\
	rmt_unlocklist.c rmt_unlocklist.h	\
	rmt.c 
	
redis_migrate_tool_LDADD = $(top_builddir)/src/ae/libae.a
redis_migrate_tool_LDADD += $(top_builddir)/src/lzf/liblzf.a
redis_migrate_tool_LDADD += $(top_builddir)/src/intset/libintset.a
redis_migrate_tool_LDADD += $(top_builddir)/src/ziplist/libziplist.a
redis_migrate_tool_LDADD += $(top_builddir)/src/zipmap/libzipmap.a
redis_migrate_tool_LDADD += $(top_builddir)/dep/jemalloc-4.0.4/lib/libjemalloc.a
