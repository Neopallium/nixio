local nix = require"nixio"

local function nassert(test, rc, errmsg, ...)
	if not test then
		error(errmsg, 2)
	end
	return test, rc, errmsg, ...
end

local filename = assert(arg[1], "Need input file")
local file = nix.open(filename, "r")

local hasher = nix.crypto.hash('sha1')

repeat
  local buf = nassert(file:read(1024))
  if #buf > 0 then
    nassert(hasher:update(buf))
  else
    break
  end
until false

local hash = nassert(hasher:final())
print(hash .. "  " .. filename)
