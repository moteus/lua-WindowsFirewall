package = "WindowsFirewall"
version = "scm-0"
source = {
  url = "https://github.com/moteus/lua-WindowsFirewall/archive/master.zip",
  dir = "lua-WindowsFirewall-master",
}

description = {
  summary = "Windows Firewall configuration library",
  homepage = "https://github.com/moteus/lua-WindowsFirewall",
  detailed = [[]],
  license  = "MIT/X11",
}

supported_platforms = {
  "windows"
}

dependencies = {
  "lua >= 5.1, < 5.4",
  "luacom",
  "bit32",
}

build = {
  type = "builtin",
  copy_directories = {"examples"},

  modules = {
    ["WindowsFirewall" ]       = "src/WindowsFirewall.lua",
    ["WindowsFirewall.utils"]  = "src/WindowsFirewall/utils.lua",
  }
}
