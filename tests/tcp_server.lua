local nix = require"nixio"

local function nassert(test, rc, errmsg, ...)
	if not test then
		error(errmsg, 2)
	end
	return test, rc, errmsg, ...
end

local s = nix.socket('inet', 'stream')
nassert(s:setopt('socket', 'reuseaddr', 1))
nassert(s:bind('0.0.0.0', 9090))
nassert(s:listen(128))

repeat
  print('Wait for client: port 9090')
	local c, host, port = nassert(s:accept())
	print('accept():', c, host, port)
	repeat
		local buf, ip, port = nassert(c:recvfrom(100))
    if #buf > 0 then
		  print('recvfrom():', buf, ip, port)
    end
	until #buf == 0
until false

