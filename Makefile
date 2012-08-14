ifneq (,$(wildcard ../../build/config.mk))
include ../../build/config.mk
include ../../build/module.mk
include ../../build/gccconfig.mk
else
include standalone.mk
endif

NIXIO_TLS    ?= openssl
NIXIO_SO      = nixio.so
NIXIO_LDFLAGS =

ifeq (,$(findstring Darwin,$(OS)))
# library for crypt() function
	NIXIO_LDFLAGS += -lcrypt
else
	EXTRA_CFLAGS += -D__DARWIN__
	NIXIO_TLS=
endif

NIXIO_OBJ = src/nixio.o src/socket.o src/sockopt.o src/bind.o src/address.o \
	    src/poll.o src/io.o src/file.o src/splice.o src/process.o src/syslog.o \
	    src/bit.o src/binary.o src/fs.o src/user.o \
	    $(if $(NIXIO_TLS),src/tls-crypto.o src/tls-context.o src/tls-socket.o,)

ifeq ($(NIXIO_TLS),axtls)
	TLS_CFLAGS = -I/usr/include/axTLS/ssl -I/usr/include/axTLS/crypto -I/usr/include/axTLS/config -include src/axtls-compat.h
	TLS_DEPENDS = src/axtls-compat.o
	NIXIO_OBJ += src/axtls-compat.o /usr/lib/libaxtls.a
endif

ifeq ($(NIXIO_TLS),openssl)
	NIXIO_LDFLAGS += -lssl
endif

ifeq ($(NIXIO_TLS),cyassl)
	NIXIO_LDFLAGS += -lcyassl
	TLS_DEPENDS = src/cyassl-compat.o
	TLS_CFLAGS = -include src/cyassl-compat.h
	NIXIO_OBJ += src/cyassl-compat.o
endif

ifeq ($(NIXIO_TLS),)
	NIXIO_CFLAGS += -DNO_TLS
endif


ifeq ($(OS),SunOS)
	NIXIO_LDFLAGS += -lsocket -lnsl -lsendfile
endif

ifneq (,$(findstring MINGW,$(OS))$(findstring mingw,$(OS))$(findstring Windows,$(OS)))
	NIXIO_CROSS_CC:=$(shell which i586-mingw32msvc-cc)
ifneq (,$(NIXIO_CROSS_CC))
	CC:=$(NIXIO_CROSS_CC)
endif
	NIXIO_OBJ += src/mingw-compat.o
	NIXIO_LDFLAGS_POST:=-llua -lssl -lcrypto -lws2_32 -lgdi32
	FPIC:=
	EXTRA_CFLAGS += -D_WIN32_WINNT=0x0501
	LUA_CFLAGS:=
	NIXIO_SO:=nixio.dll
	NIXIO_LDFLAGS:=
endif


%.o: %.c
	$(COMPILE) $(NIXIO_CFLAGS) $(LUA_CFLAGS) $(FPIC) -c -o $@ $< 

ifneq ($(NIXIO_TLS),)
src/tls-crypto.o: $(TLS_DEPENDS) src/tls-crypto.c
	$(COMPILE) $(NIXIO_CFLAGS) $(LUA_CFLAGS) $(FPIC) $(TLS_CFLAGS) -c -o $@ src/tls-crypto.c

src/tls-context.o: $(TLS_DEPENDS) src/tls-context.c
	$(COMPILE) $(NIXIO_CFLAGS) $(LUA_CFLAGS) $(FPIC) $(TLS_CFLAGS) -c -o $@ src/tls-context.c
	
src/tls-socket.o: $(TLS_DEPENDS) src/tls-socket.c
	$(COMPILE) $(NIXIO_CFLAGS) $(LUA_CFLAGS) $(FPIC) $(TLS_CFLAGS) -c -o $@ src/tls-socket.c
	
src/axtls-compat.o: /usr/lib/libaxtls.a src/axtls-compat.c
	$(COMPILE) $(NIXIO_CFLAGS) $(LUA_CFLAGS) $(FPIC) $(TLS_CFLAGS) -c -o $@ src/axtls-compat.c
	mkdir -p dist
endif	

compile: $(NIXIO_OBJ)
	$(LINK) $(SHLIB_FLAGS) -o src/$(NIXIO_SO) $(NIXIO_OBJ) $(NIXIO_LDFLAGS) $(NIXIO_LDFLAGS_POST)
	mkdir -p dist$(LUA_LIBRARYDIR)
	cp src/$(NIXIO_SO) dist$(LUA_LIBRARYDIR)/$(NIXIO_SO)

clean: luaclean
	rm -f src/*.o src/*.so src/*.a src/*.dll

install: build
	cp -pR dist$(LUA_MODULEDIR)/* $(LUA_MODULEDIR)
	cp -pR dist$(LUA_LIBRARYDIR)/* $(LUA_LIBRARYDIR)
