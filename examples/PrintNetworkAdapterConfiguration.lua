package.path = package.path .. ';..\\src\\?.lua'

local utils = require "WindowsFirewall.utils"

local t = function(v, s)
  if type(v)=='table' then
    return table.concat(v, s)
  end
  return v
end

utils.EachNetworkAdapterConfiguration(function(adapter)
  print ("--------------------------------------------------"             )
  print ("  Win32_NetworkAdapterConfiguration instance: ", adapter:Index())
  print ("--------------------------------------------------"             )

  local strIPAddress                  = t(adapter:IPAddress(),                  ", ")
  local strIPSubnet                   = t(adapter:IPSubnet(),                   ", ")
  local strGatewayCostMetric          = t(adapter:GatewayCostMetric(),          ", ")
  local strDefaultIPGateway           = t(adapter:DefaultIPGateway(),           ", ")
  local strDNSDomainSuffixSearchOrder = t(adapter:DNSDomainSuffixSearchOrder(), ", ")
  local strDNSServerSearchOrder       = t(adapter:DNSServerSearchOrder(),       ", ")
  local strIPSecPermitIPProtocols     = t(adapter:IPSecPermitIPProtocols(),     ", ")
  local strIPSecPermitTCPPorts        = t(adapter:IPSecPermitTCPPorts(),        ", ")
  local strIPSecPermitUDPPorts        = t(adapter:IPSecPermitUDPPorts(),        ", ")
  local strIPXFrameType               = t(adapter:IPXFrameType(),               ", ")
  local strIPXNetworkNumber           = t(adapter:IPXNetworkNumber(),           ", ")

  print( "MACAddress                  : ", adapter:MACAddress()                    )
  print( "Description                 : ", adapter:Description()                   )
  print( "DHCPEnabled                 : ", adapter:DHCPEnabled()                   )

  print( "IPAddress                   : ", strIPAddress                            )
  print( "IPSubnet                    : ", strIPSubnet                             )
  print( "IPEnabled                   : ", adapter:IPEnabled()                     )
  print( "DefaultIPGateway            : ", strDefaultIPGateway                     )
  print( "GatewayCostMetric           : ", strGatewayCostMetric                    )

  print( "IPConnectionMetric          : ", adapter:IPConnectionMetric()            )
  print( "DHCPLeaseExpires            : ", adapter:DHCPLeaseExpires()              )
  print( "DHCPLeaseObtained           : ", adapter:DHCPLeaseObtained()             )
  print( "DHCPServer                  : ", adapter:DHCPServer()                    )
  print( "DNSDomain                   : ", adapter:DNSDomain()                     )
  print( "IPFilterSecurityEnabled     : ", adapter:IPFilterSecurityEnabled()       )
  print( "IPPortSecurityEnabled       : ", adapter:IPPortSecurityEnabled()         )

  print( "DNSDomainSuffixSearchOrder  : ", strDNSDomainSuffixSearchOrder           )
  print( "DNSEnabledForWINSResolution : ", adapter:DNSEnabledForWINSResolution()   )
  print( "DNSHostName                 : ", adapter:DNSHostName()                   )

  print( "DNSServerSearchOrder        : ",  strDNSServerSearchOrder                )
  print( "DomainDNSRegistrationEnabled: ",  adapter:DomainDNSRegistrationEnabled() )
  print( "ForwardBufferMemory         : ",  adapter:ForwardBufferMemory()          )
  print( "FullDNSRegistrationEnabled  : ",  adapter:FullDNSRegistrationEnabled()   )

  print( "IGMPLevel                   : ", adapter:IGMPLevel()                     )
  print( "Index                       : ", adapter:Index()                         )

  print( "IPSecPermitIPProtocols      : ", strIPSecPermitIPProtocols               )
  print( "IPSecPermitTCPPorts         : ", strIPSecPermitTCPPorts                  )
  print( "IPSecPermitUDPPorts         : ", strIPSecPermitUDPPorts                  )

  print( "IPUseZeroBroadcast          : ", adapter:IPUseZeroBroadcast()            )
  print( "IPXAddress                  : ", adapter:IPXAddress()                    )
  print( "IPXEnabled                  : ", adapter:IPXEnabled()                    )

  print( "IPXFrameType                : ", strIPXFrameType                         )

  print( "IPXNetworkNumber            : ", strIPXNetworkNumber                     )
  print( "IPXVirtualNetNumber         : ", adapter:IPXVirtualNetNumber()           )
  print( "KeepAliveInterval           : ", adapter:KeepAliveInterval()             )

  print( "KeepAliveTime               : ", adapter:KeepAliveTime()                 )
  print( "MTU                         : ", adapter:MTU()                           )
  print( "NumForwardPackets           : ", adapter:NumForwardPackets()             )
  print( "PMTUBHDetectEnabled         : ", adapter:PMTUBHDetectEnabled()           )
  print( "PMTUDiscoveryEnabled        : ", adapter:PMTUDiscoveryEnabled()          )
  print( "ServiceName                 : ", adapter:ServiceName()                   )
  print( "SettingID                   : ", adapter:SettingID()                     )
  print( "TcpipNetbiosOptions         : ", adapter:TcpipNetbiosOptions()           )
  print( "TcpMaxConnectRetransmissions: ", adapter:TcpMaxConnectRetransmissions()  )
  print( "TcpMaxDataRetransmissions   : ", adapter:TcpMaxDataRetransmissions()     )
  print( "TcpNumConnections           : ", adapter:TcpNumConnections()             )
  print( "TcpUseRFC1122UrgentPointer  : ", adapter:TcpUseRFC1122UrgentPointer()    )
  print( "TcpWindowSize               : ", adapter:TcpWindowSize()                 )
  print( "WINSEnableLMHostsLookup     : ", adapter:WINSEnableLMHostsLookup()       )
  print( "WINSHostLookupFile          : ", adapter:WINSHostLookupFile()            )
  print( "WINSPrimaryServer           : ", adapter:WINSPrimaryServer()             )
  print( "WINSScopeID                 : ", adapter:WINSScopeID()                   )
  print( "WINSSecondaryServer         : ", adapter:WINSSecondaryServer()           )
  print( "ArpAlwaysSourceRoute        : ", adapter:ArpAlwaysSourceRoute()          )
  print( "ArpUseEtherSNAP             : ", adapter:ArpUseEtherSNAP()               )
  print( "DatabasePath                : ", adapter:DatabasePath()                  )
  print( "DeadGWDetectEnabled         : ", adapter:DeadGWDetectEnabled()           )

  print( "DefaultTOS                  : ", adapter:DefaultTOS()                    )
  print( "DefaultTTL                  : ", adapter:DefaultTTL()                    )
end)
