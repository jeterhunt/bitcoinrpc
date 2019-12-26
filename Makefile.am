AUTOMAKE_OPTIONS=subdir-objects

DIST_SUBDIRS = univalue
EXTRA_LIBRARIES = 

#if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
#else
#LIBUNIVALUE = $(UNIVALUE_LIBS)
#endif
BOOST_LIBS=-lboost_regex -lboost_system -lboost_filesystem -lboost_thread -lboost_program_options
GMCRYPTO_INCLUDES= -I$(srcdir)/univalue/include $(UNIVALUE_CFLAGS) -I$(srcdir)/openssl/include

bin_PROGRAMS = gmcrypto
gmcrypto_SOURCES = \
  init.h \
  init.cpp \
  sync.h \
  sync.cpp \
  netaddress.h \
  netaddress.cpp \
  httpserver.h \
  httpserver.cpp \
  httprpc.h \
  httprpc.cpp \
  gmcrypto.cpp \
  netbase.h \
  netbase.cpp \
  util.h \
  util.cpp \
  utilstrencodings.h \
  utilstrencodings.cpp \
  tinyformat.h \
  threadsafety.h \
  rpc/server.h \
  rpc/server.cpp \
  rpc/protocol.h \
  rpc/protocol.cpp \
  rpc/register.h \
  rpc/maingmcrypto.cpp \
  crypto/crypto_include/base_64.h \
  crypto/crypto_src/base_64.cpp\
  crypto/crypto_include/base_58.h \
  crypto/crypto_src/base_58.cpp \
  crypto/crypto_include/hexTranscode.h \
  crypto/crypto_src/hexTranscode.cpp \
  crypto/crypto_include/cryptography.h \
  crypto/crypto_src/cryptography.cpp \
  crypto/crypto_src/judgeInputParameters.h\
  crypto/crypto_src/judgeInputParameters.cpp
  

#gmcrypto_LDFLAGS = -pthread -levent_pthreads -L$(srcdir)/openssl/lib -L/usr/lib
gmcrypto_LDFLAGS = -pthread -levent_pthreads -L$(srcdir)/openssl/lib 
gmcrypto_CPPFLAGS = $(GMCRYPTO_INCLUDES)
gmcrypto_CXXFLAGS = -std=c++11 
gmcrypto_LDADD = $(BOOST_LIBS) -lpthread -levent $(LIBUNIVALUE)  -lcrypto  -levent_openssl
