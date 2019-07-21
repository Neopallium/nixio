#!/usr/bin/env lua

package = "nixio"
version = "0.4-1"
source = {
	url = "git://github.com/spiccinini/nixio.git",
	tag = "v0.4",
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
	homepage = "http://luci.subsignal.org",
	license = "Apache 2.0",
	maintainer = "Robert G. Jakabosky <bobby@sharedrealm.com>",
}
dependencies = {
	"lua >= 5.1"
}
external_dependencies = {
	platforms = {
		macosx = {
			-- OpenSSL deprecated on Mac OSX Lion
			OPENSSL = {},
		}
	},
	OPENSSL = {
		header = "openssl/ssl.h",
	}
}
build = {
	platforms = {
		macosx = {
			build_variables = {
				NIXIO_TLS = "",
				NIXIO_LDFLAGS = "",
				LUA_CFLAGS = "$(CFLAGS) -I$(LUA_INCDIR)",
			},
		}
	},
	type = "make",
	build_variables = {
		NIXIO_LDFLAGS = "-lcrypto -L$(OPENSSL_LIBDIR) -I$(OPENSSL_INCDIR)",
		LUA_CFLAGS = "$(CFLAGS) -I$(LUA_INCDIR)",
	},
	install_variables = {
		LUA_MODULEDIR = "$(LUADIR)",
		LUA_LIBRARYDIR = "$(LIBDIR)",
	},
}
