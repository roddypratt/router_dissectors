-- Nevion MRP Protocol dissector for Wireshark.
--
-- Copyright (C) 2021 Rascular Technology Ltd.
--------------------------------------------------------------
local nevion = Proto("nevion", "Nevion MRP protocol");

local f_command = ProtoField.string("nevion.command", "Command");
local f_response = ProtoField.string("nevion.response", "Response");
local f_status = ProtoField.string("nevion.status", "Status");
local f_body = ProtoField.string("nevion.body", "Body");

nevion.fields = {f_command, f_status, f_response, f_body};

-- local ef_checkum = ProtoExpert.new("nevion.checksum.expert",
--                                      "Bad checksum", expert.group.MALFORMED,
--                                      expert.severity.ERROR);

-- nevion.experts = {ef_checkum}

function rangeChar(range, i)
    local r = range:range(i, 1)
    return r, r:uint()
end

function rangeString(range, i, len)
    local r = range:range(i, len)
    return r, r:string()
end

function processPacket(mess, root, range)
    local tree = root:add(range, "Nevion MRP")

    local c = mess:sub(1, 1)
    local eol = string.find(mess, "\n")
    if c == "?" then
        tree:add(f_response, rangeString(range, 0, eol - 1))
    elseif c == "%" then
        tree:add(f_status, rangeString(range, 0, eol - 1))
    else
        tree:add(f_command, rangeString(range, 0, eol - 1))
    end
    if eol and eol < #mess then
        tree:add(f_body, rangeString(range, eol, #mess - eol))
    end
end

function nevion.dissector(tvb, pinfo, root_tree)

    pinfo.cols.protocol = "Nevion MRP";
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

    for p = startpos, len - 2 do
        local c = string.char(bytes:get_index(p))
        if (c == '\n') and (string.char(bytes:get_index(p + 1)) == '\n') then
            local range = tvb:range(startpos, #mess + 2)
            processPacket(mess .. "\n", root_tree, range)
            return startpos, #mess + 2
        else
            mess = mess .. c
        end
    end
    return startpos -- end not found - keep looking
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(4381, nevion)

