package = "nixio"
version = "0.4.1-1"
source = {
	url = "git://github.com/Neopallium/nixio.git",
  branch = "v0.4.1"
}
description = {
   summary = "System, Networking and I/O library for Lua",
   detailed = [[
      Nixio is a multi-platform library offering a wide variety
      of features such as IPv4, IPv6 and UNIX networking, large file I/O, file
      system operations, system and process control, POSIX user/group management,
      basic cryptographical hashing, hmac and TLS support, bit operations and
      binary conversion.
   ]],
   homepage = "http://github.com/Neopallium/nixio",
   license = "Apache 2.0",
   maintainer = "Steven Barth",
}
dependencies = {
   "lua >= 5.1"
}
external_dependencies = {
   OPENSSL = {
      header = "openssl/ssl.h",
   }
}
build = {
   type = "make",
   build_variables = {
      NIXIO_LDFLAGS = "-lcrypt -L$(OPENSSL_LIBDIR) -I$(OPENSSL_INCDIR)",
      LUA_CFLAGS = "$(CFLAGS) -I$(LUA_INCDIR)",
   },
   install_variables = {
      LUA_MODULEDIR = "$(LUADIR)",
      LUA_LIBRARYDIR = "$(LIBDIR)",
   },
}
