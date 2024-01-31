-- Leitch Pass-Through Protocol dissector for Wireshark.
--
-- Copyright (C) 2024 Rascular Technology Ltd.
--------------------------------------------------------------
local leitch = Proto("Leitch", "Leitch Pass-Through protocol");

local f_command = ProtoField.string("leitch.command", "Command");
local f_response = ProtoField.string("leitch.response", "Response");
local f_body = ProtoField.string("leitch.body", "Body");

leitch.fields = { f_command, f_response, f_body };

function rangeChar(range, i)
    local r = range:range(i, 1)
    return r, r:uint()
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

    elseif checkResponse(tree, mess, range, "S:", "Crosspoint Status") then
    elseif checkResponse(tree, mess, range, "V:", "Preset Crosspoint Status") then
    elseif checkResponse(tree, mess, range, "F:", "Frame Size") then
    elseif checkResponse(tree, mess, range, "Q:", "Alarm Status") then
    elseif checkResponse(tree, mess, range, "W!", "Lock/Unlock Status") then
    elseif checkResponse(tree, mess, range, "I!", "Information") then
    elseif checkResponse(tree, mess, range, ">", "Prompt") then
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
