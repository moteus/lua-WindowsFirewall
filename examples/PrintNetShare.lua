package.path = package.path .. ';..\\src\\?.lua'

local utils = require "WindowsFirewall.utils"

utils.EachNetShare(function(cnn, props)
  print("Name       : ", props.Name       )
  print("Guid       : ", props.Guid       )
  print("DeviceName : ", props.DeviceName )
  print("Status     : ", props.Status     )
  print("MediaType  : ", props.MediaType  )
  print("***********************************************")
end)
