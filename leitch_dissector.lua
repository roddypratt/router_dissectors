-- Leitch Pass-Through Protocol dissector for Wireshark.
--
-- Copyright (C) 2024 Rascular Technology Ltd.
--------------------------------------------------------------
local leitch = Proto("Leitch", "Leitch Pass-Through protocol");

local f_command = ProtoField.string("leitch.command", "Command");
local f_response = ProtoField.string("leitch.response", "Response");
local f_body = ProtoField.string("leitch.body", "Body");

local f_name = ProtoField.string("leitch.name", "Name");
local f_levels = ProtoField.string("leitch.levels", "Levels");
local f_source = ProtoField.uint16("leitch.source", "Source");
local f_dest = ProtoField.uint16("leitch.dest", "Dest");
leitch.fields = { f_command, f_response, f_body, f_source, f_dest, f_name, f_levels };

function rangeHex(range, i, len)
    local r = range:range(i, len)
    return r, tonumber(r:string(), 16)
end

function rangeString(range, i, len)
    local r = range:range(i, len)
    return r, r:string()
end

local function starts_with(str, start) return str:sub(1, #start) == start end

function checkCommand(tree, mess, range, cmd, cmdName)
    if starts_with(mess, cmd) then
        tree:add(f_command, range:range(0, #cmd), cmdName)
        return true
    end
    return false
end

function checkResponse(tree, mess, range, cmd, cmdName)
    if starts_with(mess, cmd) then
        tree:add(f_response, range:range(0, #cmd), cmdName)
        return true
    end
    return false
end

function processPacket(mess, root, range)
    local tree = root:add(range, "Leitch Pass-Through")


    if checkCommand(tree, mess, range, "@ !", "Disable Reporting") then
    elseif checkCommand(tree, mess, range, "@ ?", "Enable Reporting") then
    elseif checkCommand(tree, mess, range, "@ Z:", "Reset Levels") then
    elseif checkCommand(tree, mess, range, "@ X:", "Crosspoint Take") then
        local l, d, s = string.match(mess, "^@ X:(%x+)/(%x+),(%x+)")
        tree:add(f_levels, rangeString(range, 4, #l))
        tree:add(f_dest, rangeHex(range, 5 + #l, #d))
        tree:add(f_source, rangeHex(range, 6 + #l + #d, #s))
    elseif checkCommand(tree, mess, range, "@ S?", "Crosspoint Status Request") then
    elseif checkCommand(tree, mess, range, "@ Z:", "Reset Levels") then
    elseif checkCommand(tree, mess, range, "@ P:", "Preset Crosspoint") then
    elseif checkCommand(tree, mess, range, "@ X?", "Crosspoint Status Request") then
    elseif checkCommand(tree, mess, range, "@ p?", "Preset CrosspointStatus Request") then
    elseif checkCommand(tree, mess, range, "@ V?", "Preset CrosspointStatus Request") then
    elseif checkCommand(tree, mess, range, "@ Q?/", "Alarm Status Request") then
    elseif checkCommand(tree, mess, range, "@ F?", "Frame Size Request") then
    elseif checkCommand(tree, mess, range, "@ I?", "Information Request") then
    elseif checkCommand(tree, mess, range, "@ W:", "Lock/Unlock Request") then
    elseif checkCommand(tree, mess, range, "@ B:C", "Clear Presets") then
    elseif checkCommand(tree, mess, range, "@ B:E", "Execute Presets") then
    elseif checkCommand(tree, mess, range, "@ B:R", "Reset Presets") then
    elseif checkCommand(tree, mess, range, "@ K?", "Router Names Request") then
        local sd, s = string.match(mess, "^@ K%?(%a)%a,(%x+)")
        if sd == 'S' then
            tree:add(f_source, rangeHex(range, 7, #s))
        elseif sd == 'D' then
            tree:add(f_dest, rangeHex(range, 7, #s))
        end
    elseif checkResponse(tree, mess, range, ">", "Prompt") then
    elseif checkResponse(tree, mess, range, "S:", "Crosspoint Status") then
        local l, d, s = string.match(mess, "^S:(%x)(%x+),(%x+)")
        tree:add(f_levels, rangeHex(range, 2, #l))
        tree:add(f_dest, rangeHex(range, 2 + #l, #d))
        tree:add(f_source, rangeHex(range, 3 + #l + #d, #s))
    elseif checkResponse(tree, mess, range, "V:", "Preset Crosspoint Status") then
    elseif checkResponse(tree, mess, range, "F:", "Frame Size") then
    elseif checkResponse(tree, mess, range, "Q:", "Alarm Status") then
    elseif checkResponse(tree, mess, range, "W!", "Lock/Unlock Status") then
    elseif checkResponse(tree, mess, range, "I!", "Information") then
    elseif checkResponse(tree, mess, range, "K:", "Router Name") then
        local sd, s = string.match(mess, "^K:(%a)%a(%x+)")
        if sd == 'S' then
            tree:add(f_source, rangeHex(range, 4, #s))
        elseif sd == 'D' then
            tree:add(f_dest, rangeHex(range, 4, #s))
        end
        local n = string.sub(mess, 6 + #s, #mess)
        tree:add(f_name, range:range(5 + #s, #n), Struct.fromhex(n))
    else
        tree:add(f_response, range, "Unknown")
    end

    tree:add(f_body, rangeString(range, 0, #mess))
end

function leitch.dissector(tvb, pinfo, root_tree)
    pinfo.cols.protocol = "Leitch";
    local p = 0
    while p < tvb:len() do
        local st, l = lookForPacket(tvb, root_tree, p)
        if l then
            p = st + l;
        else
            pinfo.desegment_offset = st
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end
    end
end

function lookForPacket(tvb, root_tree, startpos)
    local bytes = tvb:bytes();
    local len = bytes:len()
    local mess = ""

    for p = startpos, len - 1 do
        local c = string.char(bytes:get_index(p))
        if (c ~= '\r') and (c ~= '\n') then -- ignore CR and LF
            mess = mess .. c
        end
        if (c == '\r') or (c == '>') then
            local range = tvb:range(startpos, (p - startpos) + 1)
            processPacket(mess, root_tree, range)
            return startpos, (p - startpos) + 1
        end
    end
    return startpos -- end not found - keep looking
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(23, leitch)
