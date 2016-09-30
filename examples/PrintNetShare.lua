package.path = package.path .. ';..\\src\\?.lua'

local utils = require "WindowsFirewall.utils"

utils.EachNetShare(function(cnn, props)
  local szMsg = "Enabling Firwall on connection:"           .. "\n" ..
                "   Name       : " ..  props.Name           .. "\n" ..
                "   Guid       : " ..  props.Guid           .. "\n" ..
                "   DeviceName : " ..  props.DeviceName     .. "\n" ..
                "   Status     : " ..  props.Status         .. "\n" ..
                "   MediaType  : " ..  props.MediaType      .. "\n" ..
                "***********************************************\n"
  print(szMsg)
end)
