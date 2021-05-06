# Wireshark Lua dissectors for Video Routers

| Protocol        | Filename               | Default port | Wireshark proto |
| --------        | --------               | ------------ | --------------- |
| Pro-Bel SW-P-08 | `probel_dissector.lua` | 2007, 2008   | SWP08           |

## Using the Dissectors

Either copy `xxx_dissector.lua` to your Wireshark plugins folder, or start wireshark (e.g. from Powershell) like this:

`& "c:\program files\wireshark\wireshark.exe" -X lua_script:probel_dissector.lua`

If your router is using a different TCP port you can use wireshark's "Decode As.." function to specify the port and protocol.

Packet contents for the all common routing commands are decoded.
