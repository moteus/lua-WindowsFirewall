local ut     = require "WindowsFirewall.utils"
local luacom = require "luacom"

local _NAME    = 'WindowsFirewall'
local _VERSION = '0.1.0-dev'

local bit32    = ut.bit32
local enum     = ut.enum
local pcomcall = ut.pcomcall
local pcomset  = ut.pcomset
local pcomget  = ut.pcomget
local pcommeth = ut.pcommeth

local fwlib = luacom.LoadTypeLibrary('FirewallAPI.dll')

local C = fwlib:ExportConstants()

local FwPolicy2PROGID = "HNetCfg.FwPolicy2"
FwPolicy2CLSID = assert(luacom.CLSIDfromProgID(FwPolicy2PROGID))

local FwRulePROGID = "HNetCfg.FwRule"
FwRuleCLSID = assert(luacom.CLSIDfromProgID(FwRulePROGID))

local ProfileType = {
  Public  = C.NET_FW_PROFILE2_PUBLIC;
  Private = C.NET_FW_PROFILE2_PRIVATE;
  Domain  = C.NET_FW_PROFILE2_DOMAIN;
  All     = C.NET_FW_PROFILE2_ALL;
}

local function MaskToProfileType(v)
  return {
    Domain  = 0 ~= bit32.band(C.NET_FW_PROFILE2_DOMAIN,  v);
    Private = 0 ~= bit32.band(C.NET_FW_PROFILE2_PRIVATE, v);
    Public  = 0 ~= bit32.band(C.NET_FW_PROFILE2_PUBLIC,  v);
  }
end

local function ProfileTypeToMask(t)
  local v = 0
  if type(t) == 'table' then
    local v = 0
    for k, n in pairs(t) do
      local m = ProfileType[k]
      if not m then error('unknown firewall profile type: ' .. tostring(k)) end
      if n then v = v + m end
    end
    return v
  end

  if type(t) == 'number' then
    v = t
    if t ~= ProfileType.All then
      local mask = ProfileType.Public + ProfileType.Private + ProfileType.Domain
      v = bit32.band(t, mask)
    end
    return v
  end

  error('invalid firewall profile type: ' .. type(t))
end

local function CheckProfileType(t)
  if type(t) == 'string' then
    return assert(ProfileType[t], 'unknown firewall profile type: ' .. tostring(t))
  end

  if type(t) == 'number' then return t end

  error('invalid firewall profile type: ' .. type(t))
end

local RuleAction = {
  Allow = C.NET_FW_ACTION_ALLOW,
  Block = C.NET_FW_ACTION_BLOCK,
}

local function CheckRuleAction(r)
  if type(r) == 'string' then
    return assert(RuleAction[r], 'unknown rule action: ' .. r)
  end

  if type(r) == 'number' then
    assert(
      (r == RuleAction.Allow) or (r == RuleAction.Block),
      'unknown rule action: ' .. r
    )
    return r
  end

  error('invalid rule action type: ' .. type(r))
end

local function IntToRuleAction(r)
  if r == C.NET_FW_ACTION_ALLOW then return 'Allow' end
  if r == C.NET_FW_ACTION_BLOCK then return 'Block' end
  return 'Unknown'
end

local RuleDirection = {
  In  = C.NET_FW_RULE_DIR_IN,
  Out = C.NET_FW_RULE_DIR_OUT,
}

local function CheckRuleDirection(r)
  if type(r) == 'string' then
    return assert(RuleDirection[r], 'unknown rule direction: ' .. r)
  end

  if type(r) == 'number' then
    assert(
      (r == RuleDirection.In) or (r == RuleDirection.Out),
      'unknown rule direction: ' .. r
    )
    return r
  end

  error('invalid rule direction type: ' .. type(r))
end

local function IntToRuleDirection(r)
  if r == C.NET_FW_RULE_DIR_IN  then return 'In' end
  if r == C.NET_FW_RULE_DIR_OUT then return 'Out' end
  return 'Unknown'
end

local Protocol = {
  Tcp  = C.NET_FW_IP_PROTOCOL_TCP,
  Udp  = C.NET_FW_IP_PROTOCOL_UDP,
  Icmp = C.NET_FW_IP_PROTOCOL_ICMP or 1,
  Any  = C.NET_FW_IP_PROTOCOL_ANY,
}

local function InterfaceTypesToT(str)
  local a = ut.split(str, ',', true)
  local s = {}
  for i = 1, #a do
    s[a[i]] = true
  end
  return s
end

local function InterfaceTypesFromT(t)
  if type(t) == 'string' then return t end
  if type(t) == 'table' then
    -- array
    if t[1] then return table.concat(t, ',') end
    local r = ''
    for n, e in pairs(t) do
      if e then
        if #r > 0 then r = r .. ',' end
        r = r .. n
      end
    end
    return r
  end
  error('invalid rule `InterfaceType` type: ' .. type(t))
end

local FirewallRule, FirewallPolicy

-------------------------------------------------------------------------------
FirewallPolicy = ut.class() do

local REMOVE_MARK = '8c088385-4ac7-494a-83fe-af2fecfe5452'

function FirewallPolicy:__init()
  self._policy = policy or assert(luacom.CreateObject(FwPolicy2CLSID))

  return self
end

function FirewallPolicy:handle()
  return self._policy
end

function FirewallPolicy:CurrentProfileTypes()
  local v, err = pcomget(self._policy, 'CurrentProfileTypes')
  if err then return nil, err end
  return MaskToProfileType(v)
end

function FirewallPolicy:SetCurrentProfileTypes(t)
  local v = ProfileTypeToMask(t)

  local ok, err = pcomset(self._policy, 'CurrentProfileTypes', v)
  if err then return nil, err end

  return self
end

function FirewallPolicy:FirewallEnabled(profile)
  profile = CheckProfileType(profile)
  return pcomcall(self._policy.FirewallEnabled, self._policy, profile)
end

function FirewallPolicy:SetFirewallEnabled(profile, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'setFirewallEnabled', profile, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:ExcludedInterfaces(profile)
  profile = CheckProfileType(profile)
  local v, err = pcommeth(self._policy, 'ExcludedInterfaces', profile)
  if err then return nil, err end
  return v
end

function FirewallPolicy:SetExcludedInterfaces(profile, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'setExcludedInterfaces', profile, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:BlockAllInboundTraffic(profile)
  profile = CheckProfileType(profile)
  local v, err = pcommeth(self._policy, 'BlockAllInboundTraffic', profile)
  if err then return nil, err end
  return v
end

function FirewallPolicy:SetBlockAllInboundTraffic(profile, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'setBlockAllInboundTraffic', profile, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:NotificationsDisabled(profile)
  profile = CheckProfileType(profile)
  local v, err = pcommeth(self._policy, 'NotificationsDisabled', profile)
  if err then return nil, err end
  return v
end

function FirewallPolicy:SetNotificationsDisabled(profile, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'setNotificationsDisabled', profile, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:UnicastResponsesToMulticastBroadcastDisabled(profile)
  profile = CheckProfileType(profile)
  local v, err = pcommeth(self._policy, 'UnicastResponsesToMulticastBroadcastDisabled', profile)
  if err then return nil, err end
  return v
end

function FirewallPolicy:SetUnicastResponsesToMulticastBroadcastDisabled(profile, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'setUnicastResponsesToMulticastBroadcastDisabled', profile, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:Rules()
  if not self._rules then
    local rules, err = pcomget(self._policy, 'Rules')
    if not rules then return nil, err end
    self._rules = rules
  end
  return self._rules
end

function FirewallPolicy:iRules()
  local rules = assert(self:Rules())
  if not rules then return nil, err end
  return enum(rules, FirewallRule.new)
end

function FirewallPolicy:iRulesRaw()
  local rules = assert(self:Rules())
  if not rules then return nil, err end
  return enum(rules)
end

function FirewallPolicy:ServiceRestriction()
  -- INetFwServiceRestriction
  local restriction, err = pcomget(self._policy, 'ServiceRestriction')
  if not restriction then return nil, err end
  return restriction
end

function FirewallPolicy:EnableRuleGroup(profile, group, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'EnableRuleGroup', profile, group, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:IsRuleGroupEnabled(profile, group)
  profile = CheckProfileType(profile)
  local enabled, err = pcommeth(self._policy, 'IsRuleGroupEnabled', profile, group)
  if err then return nil, err end
  return enabled
end

function FirewallPolicy:RestoreLocalFirewallDefaults()
  local ok, err = pcommeth(self._policy, 'RestoreLocalFirewallDefaults')
  if err then return nil, err end
  return self
end

function FirewallPolicy:DefaultInboundAction(profile)
  profile = CheckProfileType(profile)
  local v, err = pcommeth(self._policy, 'DefaultInboundAction', profile)
  if err then return nil, err end
  return v
end

function FirewallPolicy:SetDefaultInboundAction(profile, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'setDefaultInboundAction', profile, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:DefaultOutboundAction(profile)
  profile = CheckProfileType(profile)
  local v, err = pcommeth(self._policy, 'DefaultOutboundAction', profile)
  if err then return nil, err end
  return v
end

function FirewallPolicy:SetDefaultOutboundAction(profile, value)
  profile = CheckProfileType(profile)
  local ok, err = pcommeth(self._policy, 'setDefaultOutboundAction', profile, value)
  if err then return nil, err end
  return self
end

function FirewallPolicy:IsRuleGroupCurrentlyEnabled(group)
  local enabled, err = pcommeth(self._policy, 'IsRuleGroupCurrentlyEnabled', group)
  if err then return nil, err end
  return enabled
end

function FirewallPolicy:LocalPolicyModifyState()
  local ok, err = pcommeth(self._policy, 'LocalPolicyModifyState')
  if err then return nil, err end
  return self
end

function FirewallPolicy:AddRule(rule)
  local rules, err = self:Rules()
  if not rules then return nil, err end

  local ok, err
  if luacom.GetType(rule) then
    ok, err = pcommeth(rules, 'Add', rule)
  elseif type(rule) == 'table' then 
    if getmetatable(rule) ~= FirewallRule then
      rule, err = FirewallRule.new(rule)
      if not rule then return nil, err end
    end
    ok, err = pcommeth(rules, 'Add', rule._rule)
  else
    error('invalid rule type: ' .. type(rule))
  end

  if err then return nil, err end

  return rule
end

local function RemoveCleanup(self)
  -- I do not know either it safe remove item in cycle
  local names = {} for rule in self:iRulesRaw() do
    local name = rule.Name
    if string.find(name, REMOVE_MARK) then
      names[#names + 1] = name
    end
  end

  for _, name in ipairs(names) do
    self:RemoveRule(name)
  end

  return #names
end

function FirewallPolicy:RemoveRule(rule)
  local rules, err = self:Rules()
  if not rules then return nil, err end

  local ok, err
  -- function does not retyrn anything if rule does not exists
  -- Also it only remove `first` rule with this name
  if type(rule) == 'string' then
    ok, err = pcommeth(rules, 'Remove', rule)
  elseif luacom.GetType(rule) then
    local RemoveID =  rule.Name .. ' Remove(' .. REMOVE_MARK .. ')'
    rule.Name = RemoveID
    ok, err = pcommeth(rules, 'Remove', RemoveID)
  elseif getmetatable(rule) == FirewallRule then
    local RemoveID =  rule:Name() .. ' Remove(' .. REMOVE_MARK .. ')'
    rule:SetName(RemoveID)
    ok, err = pcommeth(rules, 'Remove', RemoveID)
  else
    error('invalid rule type: ' .. type(rule))
  end

  if err then return nil, err end

  return self
end

function FirewallPolicy:FindRule(filter)
  local rules, err = self:Rules()
  if not rules then return nil, err end

  local ok, err

  if type(filter) == 'string' then
    ok, err = pcommeth(rules, 'Item', filter)
  end

  if err then return nil, err end

  -- not found
  if not ok then return end

  return FirewallRule.new(ok)
end

end
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
FirewallRule = ut.class() do

local function Set(self, r)
  if type(r) == 'string' then self:SetName(r) else
    self:SetName(r.Name)

    if nil ~= r.ApplicationName   then self:SetApplicationName  (r.ApplicationName)   end
    if nil ~= r.Description       then self:SetDescription      (r.Description)       end
    if nil ~= r.Grouping          then self:SetGrouping         (r.Grouping)          end
    if nil ~= r.Protocol          then self:SetProtocol         (r.Protocol)          end
    if nil ~= r.Direction         then self:SetDirection        (r.Direction)         end
    if nil ~= r.EdgeTraversal     then self:SetEdgeTraversal    (r.EdgeTraversal)     end

    ---! @todo set ports only if (r.Protocol ~= Protocol.Any)
    if nil ~= r.LocalPorts        then self:SetLocalPorts       (r.LocalPorts)        end
    if nil ~= r.RemotePorts       then self:SetRemotePorts      (r.RemotePorts)       end

    ---! @todo set ports only if (r.Protocol == Protocol.Icmp)
    if nil ~= r.IcmpTypesAndCodes then self:SetIcmpTypesAndCodes(r.IcmpTypesAndCodes) end

    if nil ~= r.LocalAddresses    then self:SetLocalAddresses   (r.LocalAddresses)    end
    if nil ~= r.RemoteAddresses   then self:SetRemoteAddresses  (r.RemoteAddresses)   end
    if nil ~= r.InterfaceTypes    then self:SetInterfaceTypes   (r.InterfaceTypes)    end

    if nil ~= r.Profiles          then self:SetProfiles         (r.Profiles)          end
    if nil ~= r.Action            then self:SetAction           (r.Action)            end
    if nil ~= r.ServiceName       then self:SetServiceName      (r.ServiceName)       end

    if nil ~= r.Enabled           then self:SetEnabled          (r.Enabled)           end
  end
end

function FirewallRule:__init(r)

  if luacom.GetType(r) then self._rule = r else
    assert(
      (type(r) == 'string') or (
        (type(r) == 'table') and r.Name
      ), '`Name` argument required'
    )

    self._rule = luacom.CreateObject(FwRuleCLSID)

    Set(self, r)
  end

  return self
end

function FirewallRule:handle()
  return self._rule
end

function FirewallRule:Action()
  local ok, err = pcomget(self._rule, 'Action')
  if err then return nil, err end
  return IntToRuleAction(ok)
end

function FirewallRule:SetAction(value)
  value = CheckRuleAction(value)
  local ok, err = pcomset(self._rule, 'Action', value)
  if err then return nil, err end
  return self
end

function FirewallRule:ApplicationName()
  local ok, err = pcomget(self._rule, 'ApplicationName')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetApplicationName(value)
  local ok, err = pcomset(self._rule, 'ApplicationName', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Description()
  local ok, err = pcomget(self._rule, 'Description')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetDescription(value)
  local ok, err = pcomset(self._rule, 'Description', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Direction()
  local ok, err = pcomget(self._rule, 'Direction')
  if err then return nil, err end
  return IntToRuleDirection(ok)
end

function FirewallRule:SetDirection(value)
  value = CheckRuleDirection(value)
  local ok, err = pcomset(self._rule, 'Direction', value)
  if err then return nil, err end
  return self
end

function FirewallRule:EdgeTraversal()
  local ok, err = pcomget(self._rule, 'EdgeTraversal')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetEdgeTraversal(value)
  local ok, err = pcomset(self._rule, 'EdgeTraversal', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Enabled()
  local ok, err = pcomget(self._rule, 'Enabled')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetEnabled(value)
  if type(value) == 'boolean' then value = value and 1 or 0 end
  local ok, err = pcomset(self._rule, 'Enabled', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Grouping()
  local ok, err = pcomget(self._rule, 'Grouping')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetGrouping(value)
  local ok, err = pcomset(self._rule, 'Grouping', value)
  if err then return nil, err end
  return self
end

function FirewallRule:IcmpTypesAndCodes()
  local ok, err = pcomget(self._rule, 'IcmpTypesAndCodes')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetIcmpTypesAndCodes(value)
  local ok, err = pcomset(self._rule, 'IcmpTypesAndCodes', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Interfaces()
  local ok, err = pcomget(self._rule, 'Interfaces')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetInterfaces(value)
  value = InterfaceTypesFromT(value)
  local ok, err = pcomset(self._rule, 'Interfaces', value)
  if err then return nil, err end
  return self
end

function FirewallRule:InterfaceTypes()
  local ok, err = pcomget(self._rule, 'InterfaceTypes')
  if err then return nil, err end
  return InterfaceTypesToT(ok)
end

function FirewallRule:SetInterfaceTypes(value)
  local ok, err = pcomset(self._rule, 'InterfaceTypes', value)
  if err then return nil, err end
  return self
end

function FirewallRule:LocalAddresses()
  local ok, err = pcomget(self._rule, 'LocalAddresses')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetLocalAddresses(value)
  local ok, err = pcomset(self._rule, 'LocalAddresses', value)
  if err then return nil, err end
  return self
end

function FirewallRule:LocalPorts()
  local ok, err = pcomget(self._rule, 'LocalPorts')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetLocalPorts(value)
  local ok, err = pcomset(self._rule, 'LocalPorts', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Name()
  local ok, err = pcomget(self._rule, 'Name')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetName(value)
  local ok, err = pcomset(self._rule, 'Name', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Profiles()
  local ok, err = pcomget(self._rule, 'Profiles')
  if err then return nil, err end
  return MaskToProfileType(ok)
end

function FirewallRule:SetProfiles(value)
  value = ProfileTypeToMask(value)
  local ok, err = pcomset(self._rule, 'Profiles', value)
  if err then return nil, err end
  return self
end

function FirewallRule:Protocol()
  local ok, err = pcomget(self._rule, 'Protocol')
  if err then return nil, err end
  for name, id in pairs(Protocol) do
    if id == ok then return id, name end
  end
  return ok, 'unknown'
end

function FirewallRule:SetProtocol(value)
  if type(value) == 'string' then
    value = assert(Protocol[value], 'unknown protocol: ' .. value)
  end

  local ok, err = pcomset(self._rule, 'Protocol', value)
  if err then return nil, err end
  return self
end

function FirewallRule:RemoteAddresses()
  local ok, err = pcomget(self._rule, 'RemoteAddresses')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetRemoteAddresses(value)
  local ok, err = pcomset(self._rule, 'RemoteAddresses', value)
  if err then return nil, err end
  return self
end

function FirewallRule:RemotePorts()
  local ok, err = pcomget(self._rule, 'RemotePorts')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetRemotePorts(value)
  local ok, err = pcomset(self._rule, 'RemotePorts', value)
  if err then return nil, err end
  return self
end

function FirewallRule:ServiceName()
  local ok, err = pcomget(self._rule, 'ServiceName')
  if err then return nil, err end
  return ok
end

function FirewallRule:SetServiceName(value)
  local ok, err = pcomset(self._rule, 'ServiceName', value)
  if err then return nil, err end
  return self
end

function FirewallRule:print()
  local pp = require "pp"

  pp("Name:",            self:Name())
  pp("Action:",          self:Action())
  pp("ApplicationName:", self:ApplicationName())
  pp("Description:",     self:Description())
  pp("Direction:", self:Direction())
  pp("EdgeTraversal:", self:EdgeTraversal())
  pp("Enabled:", self:Enabled())
  pp("Grouping:", self:Grouping())
  pp("IcmpTypesAndCodes:", self:IcmpTypesAndCodes())
  pp("Interfaces:", self:Interfaces())
  pp("InterfaceTypes:", self:InterfaceTypes())
  pp("LocalAddresses:", self:LocalAddresses())
  pp("LocalPorts:", self:LocalPorts())
  pp("Profiles:", self:Profiles())
  pp("Protocol:", self:Protocol())
  pp("RemoteAddresses:", self:RemoteAddresses())
  pp("RemotePorts:", self:RemotePorts())
  pp("ServiceName:", self:ServiceName())
end

end
-------------------------------------------------------------------------------

return {
  _NAME    = _NAME;
  _VERSION = _VERSION;
  Policy   = FirewallPolicy.new;
  Rule     = FirewallRule.new;
}