-- A peer for the interop matrix, written against lua-sec.
--
--   lua lua-sec-peer.lua client <host> <port> <ca.pem> [alpn=a,b] [cert=PATH key=PATH] [versions=12|13]
--   lua lua-sec-peer.lua server <port> <cert.pem> <key.pem> [alpn=a,b] [clientca=PATH] [versions=12|13]
--
-- Both sides speak lines: the server answers every line it reads with the same line, and the
-- client sends one and reads it back.
--
-- lua-sec is a binding over OpenSSL rather than a second engine, so what it adds to the matrix is a
-- third way of driving that library — through Lua's own I/O model, with LuaSec's defaults rather
-- than `ssl`'s or pyOpenSSL's. It exposes no version or cipher accessor, so a client case asserts
-- the version on the *server's* summary line, which is what the wolfSSL and pyOpenSSL sections
-- already do; what this end reports is ALPN and whether the chain verified.

local ssl = require("ssl")

local function fail(message)
  io.stderr:write("lua-sec-peer: " .. message .. "\n")
  os.exit(1)
end

local function parse(args, from)
  local opts = { alpn = nil, cert = nil, key = nil, clientca = nil, versions = nil }
  for i = from, #args do
    local arg = args[i]
    local key, value = arg:match("^(%w+)=(.*)$")
    if key == "alpn" then
      opts.alpn = {}
      for one in value:gmatch("[^,]+") do
        opts.alpn[#opts.alpn + 1] = one
      end
    elseif key == "cert" then
      opts.cert = value
    elseif key == "key" then
      opts.key = value
    elseif key == "clientca" or key == "cafile" then
      opts.clientca = value
    elseif key == "versions" then
      opts.versions = value
    elseif arg == "resume" or arg == "early" then
      -- LuaSec has no session export, so a resumption cannot be asked of this peer; the case for
      -- it lives with the peers that do. Nothing to do here.
    else
      fail("unknown option: " .. arg)
    end
  end
  return opts
end

local function protocol(opts)
  if opts.versions == "12" then
    return "tlsv1_2"
  elseif opts.versions == "13" then
    return "tlsv1_3"
  end
  return "any"
end

local function params(opts)
  local cfg = {
    protocol = protocol(opts),
    options = { "all", "no_sslv2", "no_sslv3" },
  }
  if opts.alpn then
    cfg.alpn = opts.alpn
  end
  if opts.cert then
    cfg.certificate = opts.cert
  end
  if opts.key then
    cfg.key = opts.key
  end
  if opts.clientca then
    cfg.cafile = opts.clientca
  end
  return cfg
end

local function read_line(conn)
  local line, err = conn:receive("*l")
  if not line then
    return nil, err
  end
  return line
end

local function client(args)
  if #args < 3 then
    fail("client <host> <port> <ca.pem> [options]")
  end
  local host, port, ca = args[1], tonumber(args[2]), args[3]
  local opts = parse(args, 4)
  opts.clientca = opts.clientca or ca

  local cfg = params(opts)
  cfg.mode = "client"
  cfg.verify = "peer"

  local sock = require("socket").tcp()
  sock:settimeout(20)
  local ok, err = sock:connect(host, port)
  if not ok then
    fail("connect: " .. tostring(err))
  end
  local conn, wrap_err = ssl.wrap(sock, cfg)
  if not conn then
    fail("wrap: " .. tostring(wrap_err))
  end
  conn:settimeout(20)
  local done, hs_err = conn:dohandshake()
  if not done then
    fail("handshake: " .. tostring(hs_err))
  end

  conn:send("ping\n")
  local line, read_err = read_line(conn)
  if not line then
    fail("read: " .. tostring(read_err))
  end

  local alpn = conn:getalpn() or "-"
  -- A boolean in 1.3: true when the chain reached a trusted root.
  local verified = conn:getpeerverification() and 1 or 0
  print(string.format(
    "ok version=- suite=- alpn=%s sni=- resumed=0 early=0 verified=%d bytes=%d first=%s",
    alpn, verified, #line, line))
  conn:close()
end

local function server(args)
  if #args < 3 then
    fail("server <port> <cert.pem> <key.pem> [options]")
  end
  local port, cert, key = tonumber(args[1]), args[2], args[3]
  local opts = parse(args, 4)

  local cfg = params(opts)
  cfg.mode = "server"
  cfg.certificate = cert
  cfg.key = key
  -- OpenSSL ignores `fail_if_no_peer_cert` unless `peer` is set with it: `peer` is what sends the
  -- CertificateRequest, and the other flag is what refuses a client that answers it with nothing.
  cfg.verify = opts.clientca and { "peer", "fail_if_no_peer_cert" } or "none"

  -- The context is built once, and `ssl.wrap` with a *table* is not used: a table goes through
  -- `ssl.newcontext` but a context built here is where `verify` reaches `SSL_CTX_set_verify`.
  local ctx = ssl.newcontext(cfg)
  if not ctx then
    fail("context: " .. tostring(cfg))
  end

  local listener = assert(require("socket").bind("*", port))
  listener:settimeout(0)
  io.stderr:write("listening on " .. port .. "\n")

  while true do
    local raw = listener:accept()
    if raw then
      raw:settimeout(20)
      local conn = ssl.wrap(raw, ctx)
      if conn then
        conn:settimeout(20)
        local done = conn:dohandshake()
        if done then
          while true do
            local line = read_line(conn)
            if not line then
              break
            end
            local sent, send_err = conn:send(line .. "\n")
            if not sent then
              io.stderr:write("send: " .. tostring(send_err) .. "\n")
              break
            end
          end
        else
          io.stderr:write("handshake failed\n")
        end
        conn:close()
      end
    else
      require("socket").sleep(0.01)
    end
  end
end

local argv = { ... }
if #argv == 0 then
  fail("client|server")
end
-- The subcommands index from 1, so the mode is dropped and the rest renumbered.
local rest = {}
for i = 2, #argv do
  rest[i - 1] = argv[i]
end
if argv[1] == "client" then
  client(rest)
elseif argv[1] == "server" then
  server(rest)
else
  fail("unknown mode " .. argv[1])
end
