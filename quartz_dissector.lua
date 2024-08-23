-- Evertz/Quartz Protocol dissector for Wireshark.
--
-- Copyright (C) 2021 Rascular Technology Ltd.
--------------------------------------------------------------
local quartz = Proto("quartz", "Quartz Type 1 RCP protocol");

local f_command = ProtoField.string("quartz.command", "Command");
local f_response = ProtoField.string("quartz.response", "Response");
local f_status = ProtoField.string("quartz.status", "Status");
local f_body = ProtoField.string("quartz.body", "Body");

quartz.fields = { f_command, f_status, f_response, f_body };


local ef_error = ProtoExpert.new("quartz.error.expert", "Error Response",
    expert.group.RESPONSE_CODE,
    expert.severity.ERROR);

quartz.experts = { ef_error }
function rangeChar(range, i)
    local r = range:range(i, 1)
    return r, r:uint()
end

function rangeString(range, i, len)
    local r = range:range(i, len)
    return r, r:string()
end

local function starts_with(str, start) return str:sub(1, #start) == start end

function processPacket(mess, root, range)
    local tree = root:add(range, "Quartz RCP")

    if starts_with(mess, ".S") then
        tree:add(f_command, range:range(0, 2), "SET")
    elseif starts_with(mess, ".A") then
        tree:add(f_command, range:range(0, 2), "ACK")
    elseif starts_with(mess, ".U") then
        tree:add(f_command, range:range(0, 2), "UPDATE")
    elseif starts_with(mess, ".L") then
        tree:add(f_command, range:range(0, 2), "LIST ROUTES")
    elseif starts_with(mess, ".I") then
        tree:add(f_command, range:range(0, 2), "INTERROGATE")
    elseif starts_with(mess, ".M") then
        tree:add(f_command, range:range(0, 2), "SET MULTI")
    elseif starts_with(mess, ".F") then
        tree:add(f_command, range:range(0, 2), "FIRE SALVO")
    elseif starts_with(mess, ".P") then
        tree:add(f_command, range:range(0, 2), "POWER UP")
    elseif starts_with(mess, ".BL") then
        tree:add(f_command, range:range(0, 3), "LOCK")
    elseif starts_with(mess, ".BU") then
        tree:add(f_command, range:range(0, 3), "UNLOCK")
    elseif starts_with(mess, ".BI") then
        tree:add(f_command, range:range(0, 3), "INTERROGATE LOCK")
    elseif starts_with(mess, ".BA") then
        tree:add(f_command, range:range(0, 3), "LOCK STATUS")
    elseif starts_with(mess, ".I") then
        tree:add(f_command, range:range(0, 2), "POWER UP")
    elseif starts_with(mess, ".#01") then
        tree:add(f_command, range:range(0, 4), "PING")
    elseif starts_with(mess, ".RD") then
        tree:add(f_command, range:range(0, 3), "READ DEST MNEM")
    elseif starts_with(mess, ".RS") then
        tree:add(f_command, range:range(0, 3), "READ SRC MNEM")
    elseif starts_with(mess, ".RL") then
        tree:add(f_command, range:range(0, 3), "READ LVL MNEM")
    elseif starts_with(mess, ".RAD") then
        tree:add(f_command, range:range(0, 4), "DEST MNEM")
    elseif starts_with(mess, ".RAS") then
        tree:add(f_command, range:range(0, 4), "SRC MNEM")
    elseif starts_with(mess, ".RAL") then
        tree:add(f_command, range:range(0, 4), "LVL MNEM")
    elseif starts_with(mess, ".E") then
        tree:add_proto_expert_info(ef_error)
        tree:add(f_command, range:range(0, 2), "ERROR")
    end

    tree:add(f_body, rangeString(range, 0, #mess))
end

function quartz.dissector(tvb, pinfo, root_tree)
    pinfo.cols.protocol = "Quartz";
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
        if (c == '\r') then
            local range = tvb:range(startpos, #mess)
            processPacket(mess, root_tree, range)
            return startpos, #mess + 1
        else
            mess = mess .. c
        end
    end
    return startpos -- end not found - keep looking
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(4000, quartz)
