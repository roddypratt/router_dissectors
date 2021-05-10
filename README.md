# Wireshark Lua dissectors for Video Routers

| Protocol        | Filename                     | Default port | Wireshark proto |
| --------        | --------                     | ------------ | --------------- |
| Pro-Bel SW-P-08 | `probel_swp08_dissector.lua` | 2007, 2008   | SWP08           |
| Pro-Bel SW-P-02 | `probel_swp02_dissector.lua` | 2007, 2008   | SWP02           |


## Using the Dissectors

Either copy `xxx_dissector.lua` to your Wireshark plugins folder, or start wireshark (e.g. from Powershell) like this:


`& "c:\program files\wireshark\wireshark.exe" -X lua_script:probel_swp08_dissector.lua`
`& "c:\program files\wireshark\wireshark.exe" -X lua_script:probel_swp02_dissector.lua`


If your router is using a different TCP port you can use wireshark's "Decode As.." function to specify the port and protocol.

Packet contents for the all common routing commands are decoded.

![Wireshark Screenshot](https://github.com/roddypratt/router_dissectors/screenshot.png)