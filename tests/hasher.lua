local nix = require"nixio"

local function nassert(test, rc, errmsg, ...)
	if not test then
		error(errmsg, 2)
	end
	return test, rc, errmsg, ...
end

local hash_type = arg[1] or "sha1"
local filename = assert(arg[2], "Need input file")
local file = nix.open(filename, "r")

local hasher = nix.crypto.hash(hash_type)

repeat
  local buf = nassert(file:read(1024))
  if #buf > 0 then
    nassert(hasher:update(buf))
  else
    break
  end
until false

local hash = nassert(hasher:final())
print(hash_type, hash .. "  " .. filename)

-- Test re-init
nassert(hasher:reinit())
nassert(hasher:update("test"))
local hash = nassert(hasher:final())
print("test", hash)
