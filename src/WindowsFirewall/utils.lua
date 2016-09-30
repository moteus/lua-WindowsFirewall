local bit32  = require "bit32"
local luacom = require "luacom" luacom.StartLog([[f:\e\Projects\lua-WindowsFirewall\tt.log]])
local uuid   = require "uuid"
local luacom = require "luacom"

local function class(base)
  local t = base and setmetatable({}, base) or {}
  t.__index = t
  t.__class = t
  t.__base  = base

  function t.new(...)
    local o = setmetatable({}, t)
    if o.__init then
      if t == ... then -- we call as Class:new()
        return o:__init(select(2, ...))
      else             -- we call as Class.new()
        return o:__init(...)
      end
    end
    return o
  end

  return t
end

local function enum(o, f)
  local e = luacom.GetEnumerator(o)
  if f then
    local function wrap(...)
      if ... then return f(...) end
      return ...
    end
    return function() return wrap(e:Next()) end
  end
  return function() return e:Next() end
end

local function luacom_build_error(ret)
  local typ, info, msg = string.match(ret, 'COM (.-):(%b()):(.+)$')
  if info then
    local file, line = string.match(info, '^%((.-),(%d+)%)$')
    if file then
      return string.format("[LUACOM][%s][%s:%s] %s", typ, file, line, msg)
    end
  end
  return ret
end

local function pcomcall(f, ...)
  local ok, ret = pcall(f, ...)
  if not ok then return nil, luacom_build_error(ret) end
  return ret
end

local function pcomset(o, p, v)
  local ok, ret = pcall(function() o[p] = v end)
  if not ok then return nil, luacom_build_error(ret) end
  return true
end

local function pcomget(o, p)
  local ok, ret = pcall(function() return o[p] end)
  if not ok then return nil, luacom_build_error(ret) end
  return ret
end

local function pcommeth(o, p, ...)
  local ok, ret = pcall(function() return o[p] end)
  if not ok then return nil, luacom_build_error(ret) end
  return pcomcall(ret, o, ...)
end

local function EachNetShare(cb)
  local net = luacom.CreateObject('HNetCfg.HNetShare')
  local connections = net:getEnumEveryConnection()

  for item in enum(connections) do
    local cnn   = net:INetSharingConfigurationForINetConnection(item)
    local props = net:NetConnectionProps(item)
    local ok, ret = pcall(cb, cnn, props)
    if (not ok) or ret then break end
  end

  connections, net = nil
  collectgarbage'collect'
end

local function EachNetworkAdapter(cb)
  local strComputer = "."
  local objWMIService = luacom.GetObject("winmgmts:\\\\" .. strComputer .. "\\root\\CIMV2")
  local colItems = objWMIService:ExecQuery("SELECT * FROM Win32_NetworkAdapter")

  for objItem in enum(colItems) do
    local ok, ret = pcall(cb, objItem)
    if (not ok) or ret then break end
  end

  colItems, objWMIService = nil
  collectgarbage'collect'
end

local function EachNetworkAdapterConfiguration(cb)
  local strComputer = "."
  local objWMIService = luacom.GetObject("winmgmts:\\\\" .. strComputer .. "\\root\\CIMV2")
  local colItems = objWMIService:ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration")

  for objItem in enum(colItems) do
    local ok, ret = pcall(cb, objItem)
    if (not ok) or ret then break end
  end

  colItems, objWMIService = nil
  collectgarbage'collect'
end

return {
  bit32    = bit32;
  class    = class;
  enum     = enum;
  pcomcall = pcomcall;
  pcomset  = pcomset;
  pcomget  = pcomget;
  pcommeth = pcommeth;

  EachNetShare                    = EachNetShare;
  EachNetworkAdapter              = EachNetworkAdapter;
  EachNetworkAdapterConfiguration = EachNetworkAdapterConfiguration;
}