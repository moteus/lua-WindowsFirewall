package.path = package.path .. ';..\\src\\?.lua'

local WindowsFirewall = require "WindowsFirewall"

local policy = WindowsFirewall.Policy()

local profiles = policy:CurrentProfileTypes()
for profile, exists in pairs(profiles) do
  if exists then
    local enabled = policy:FirewallEnabled(profile)
    print(string.format("On %s profile (Current) : Firewall state is %s", profile, enabled and "ON" or "OFF"))
    for rule in policy:iRules(profile) do
      print(rule:Name(), rule:Direction())
    end
  end
end

local rule = policy:AddRule{
  Name       = 'Test_Rule';
  Grouping   = 'Test group';
  Direction  = 'In';
  Action     = 'Block';
  Protocol   = 'Udp';
  LocalPorts = '449';
  Enabled    = true;
  Profiles   = { Private = true };
}
