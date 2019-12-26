
include_HEADERS = include/univalue.h
noinst_HEADERS = lib/univalue_escapes.h lib/univalue_utffilter.h

noinst_LTLIBRARIES = libunivalue.la


libunivalue_la_SOURCES = \
	lib/univalue.cpp \
	lib/univalue_read.cpp \
	lib/univalue_write.cpp

libunivalue_la_LDFLAGS = \
	-no-undefined
libunivalue_la_CXXFLAGS = -I$(top_srcdir)/univalue/include

