package.path = package.path .. ';..\\src\\?.lua'

local utils = require "WindowsFirewall.utils"

utils.EachNetworkAdapter(function(adapter)
  print("Name:        ", adapter:Name())
  print("Description: ", adapter:Description())
  print("GUID:        ", adapter:GUID())
  print("MAC:         ", adapter:MACAddress())
  print("NID:         ", adapter:NetConnectionID())
  print("ServiceName: ", adapter:ServiceName())
  print("*****************************************")
end)
