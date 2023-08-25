-- Utah RCP-3A Protocol dissector for Wireshark.
--
-- Copyright (C) 2021 Rascular Technology Ltd.
--------------------------------------------------------------
local PING = 0x03FE
local PING_REPLY = 0x03FD
local VERBOSITY = 0x0400
local VERBOSITY_REPLY = 0x0401

local TAKE = 0x1200
local TAKE_REPLY = 0x1201
local TAKE_STATUS = 0x125F
local TAKE_WITH_NODE_ID = 0x1255

local ATTRIBUTE = 0x1202
local ATTRIBUTE_REPLY = 0x1203

local MONITOR_TAKE = 0x1204
local MONITOR_TAKE_REPLY = 0x1205
local DISCONNECT = 0x1206
local DISCONNECT_REPLY = 0x1207

local SALVO = 0x1208
local SALVO_REPLY = 0x1209

local STATUS = 0x120E
local STATUS_REPLY = 0x120F

local GET_MATRIX = 0x1216
local GET_MATRIX_REPLY = 0x1217

local GET_MATRIX_ATTRIBUTES = 0x121A
local GET_MATRIX_ATTRIBUTES_REPLY = 0x121B

local GET_MONITOR_MATRIX = 0x121E
local GET_MONITOR_MATRIX_REPLY = 0x121F

local SET_LOCK = 0x122E
local SET_LOCK_REPLY = 0x122F
local GET_LOCK = 0x1230
local GET_LOCK_REPLY = 0x1231
local CLEAR_LOCK = 0x1232
local CLEAR_LOCK_REPLY = 0x1233

local DEVICE_TABLE = 0x800D
local DEVICE_TABLE_REPLY = 0x800E

local codes = {
    [PING] = "PING",
    [PING_REPLY] = "PING_REPLY",

    [VERBOSITY] = "VERBOSITY",
    [VERBOSITY_REPLY] = "VERBOSITY_REPLY",
    [TAKE] = "TAKE",
    [TAKE_REPLY] = "TAKE_REPLY",
    [TAKE_STATUS] = "TAKE_STATUS",
    [TAKE_WITH_NODE_ID] = "TAKE_WITH_NODE_ID",

    [ATTRIBUTE] = "ATTRIBUTE",
    [ATTRIBUTE_REPLY] = "ATTRIBUTE_REPLY",
    [MONITOR_TAKE] = "MONITOR_TAKE",
    [MONITOR_TAKE_REPLY] = "MONITOR_TAKE_REPLY",
    [DISCONNECT] = "DISCONNECT",
    [DISCONNECT_REPLY] = "DISCONNECT_REPLY",
    [SALVO] = "SALVO",
    [SALVO_REPLY] = "SALVO_REPLY",
    [STATUS] = "STATUS",
    [STATUS_REPLY] = "STATUS_REPLY",

    [GET_MATRIX] = "GET_MATRIX",
    [GET_MATRIX_REPLY] = "GET_MATRIX_REPLY",
    [GET_MATRIX_ATTRIBUTES] = "GET_MATRIX_ATTRIBUTES",
    [GET_MATRIX_ATTRIBUTES_REPLY] = "GET_MATRIX_ATTRIBUTES_REPLY",
    [GET_MONITOR_MATRIX] = "GET_MONITOR_MATRIX",
    [GET_MONITOR_MATRIX_REPLY] = "GET_MONITOR_MATRIX_REPLY",

    [SET_LOCK] = "SET_LOCK",
    [SET_LOCK_REPLY] = "SET_LOCK_REPLY",
    [GET_LOCK] = "GET_LOCK",
    [GET_LOCK_REPLY] = "GET_LOCK_REPLY",
    [CLEAR_LOCK] = "CLEAR_LOCK",
    [CLEAR_LOCK_REPLY] = "CLEAR_LOCK_REPLY",

    [DEVICE_TABLE] = "DEVICE_TABLE",
    [DEVICE_TABLE_REPLY] = "DEVICE_TABLE_REPLY"
}

local r_rcp3a = Proto("swp02", "Utah rcp3a protocol");

local f_opcode = ProtoField.uint16("rcp3a.op", "OpCode", base.HEX, codes);
local f_nametype = ProtoField.uint8("rcp3a.nametype", "Name Type", base.HEX,
                                    {[0] = "Sources", [1] = "Destinations"});

local f_name = ProtoField.string("rcp3a.name", "Name");

local f_source = ProtoField.uint16("rcp3a.source", "Source");
local f_dest = ProtoField.uint16("rcp3a.dest", "Dest");
local f_salvo = ProtoField.uint16("rcp3a.salvo", "Salvo");

local f_index = ProtoField.uint16("rcp3a.index", "Index");

local f_levelmap = ProtoField.uint32("rcp3a.levelmap", "Level Bits");
local f_lockmap = ProtoField.uint32("rcp3a.lockmap", "Lock Bits");
local f_verbosity = ProtoField.uint16("rcp3a.verbosity", "Verbosity");

local f_sources = ProtoField.uint16("rcp3a.sources", "Sources");
local f_dests = ProtoField.uint16("rcp3a.dests", "Dests");

local f_interface = ProtoField.uint8("rcp3a.interface", "Interface");
local f_length = ProtoField.uint16("rcp3a.length", "Length");
local f_checksum = ProtoField.uint8("rcp3a.checksum", "Checksum");

local f_status = ProtoField.uint8("rcp3a.status", "Status");

local f_count = ProtoField.uint16("rcp3a.count", "Count");
local f_panel = ProtoField.uint16("rcp3a.panel", "Panel");
local f_clear = ProtoField.uint16("rcp3a.clear", "Clear");

r_rcp3a.fields = {
    f_opcode, f_source, f_dest, f_verbosity, f_interface, f_checksum, f_sources,
    f_clear, f_dests, f_length, f_name, f_count, f_status, f_salvo, f_nametype,
    f_index, f_lockmap, f_panel
};

local ef_bad_checksum = ProtoExpert.new("rcp3a.checksum.expert", "Bad checksum",
                                        expert.group.MALFORMED,
                                        expert.severity.ERROR);

r_rcp3a.experts = {ef_bad_checksum}

function rangeByte(range, i)
    local r = range:range(i, 1)
    return r, r:uint()
end
function rangeWord(range, i)
    local r = range:range(i, 2)
    return r, r:uint()
end
function rangeLong(range, i)
    local r = range:range(i, 4)
    return r, r:uint()
end

function rangeString(range, i, len)
    local r = range:range(i, len)
    return r, "\"" .. r:stringz() .. "\""
end

function processPacket(root, range)
    local tree = root:add(range, "RCP-3A")

    tree:add(f_interface, rangeByte(range, 0))
    local r, op = rangeWord(range, 0)
    tree:add(f_opcode, r, op)
    tree:add(f_checksum, rangeByte(range, 2))

    tree:add(f_length, rangeWord(range, 4))

    local r, op = rangeWord(range, 0)

    if op == VERBOSITY_REPLY or op == VERBOSITY then
        tree:add(f_verbosity, rangeWord(range, 6))
    elseif op == TAKE or op == TAKE_REPLY or op == TAKE_WITH_NODE_ID then
        tree:add(f_source, rangeWord(range, 6))
        tree:add(f_dest, rangeWord(range, 8))
        tree:add(f_levelmap, rangeLong(range, 10))
    elseif op == TAKE_STATUS then
        tree:add(f_dest, rangeWord(range, 8))
        tree:add(f_levelmap, rangeLong(range, 10))
        tree:add(f_source, rangeWord(range, 14))
    elseif op == DISCONNECT or op == DISCONNECT_REPLY then
        tree:add(f_dest, rangeWord(range, 6))
        tree:add(f_levelmap, rangeLong(range, 8))
    elseif op == SALVO or op == SALVO_REPLY then
        tree:add(f_salvo, rangeWord(range, 6))
    elseif op == SET_LOCK or op == CLEAR_LOCK then
        tree:add(f_lockmap, rangeLong(range, 6))
        tree:add(f_levelmap, rangeLong(range, 10))
        tree:add(f_dest, rangeWord(range, 14))
        tree:add(f_panel, rangeWord(range, 16))
    elseif op == SET_LOCK_REPLY or op == CLEAR_LOCK_REPLY then
        tree:add(f_panel, rangeWord(range, 8))
        tree:add(f_dest, rangeWord(range, 10))
        tree:add(f_clear, rangeWord(range, 12))
        tree:add(f_levelmap, rangeLong(range, 14))
        tree:add(f_lockmap, rangeLong(range, 18))
    elseif op == STATUS_REPLY then
        tree:add(f_sources, rangeWord(range, 6))
        tree:add(f_dests, rangeWord(range, 8))
    elseif op == DEVICE_TABLE then
        tree:add(f_nametype, rangeByte(range, 6))
    elseif op == DEVICE_TABLE_REPLY then
        tree:add(f_nametype, rangeWord(range, 6))
        tree:add(f_index, rangeWord(range, 8))
        tree:add(f_name, rangeString(range, 10, 8))
    elseif op == GET_MATRIX or op == GET_LOCK then
        tree:add(f_dest, rangeWord(range, 6))
        tree:add(f_count, rangeWord(range, 8))
    elseif op == GET_MATRIX_REPLY then
        tree:add(f_dest, rangeWord(range, 6))
        tree:add(f_count, rangeWord(range, 8))
    end
end

function r_rcp3a.dissector(tvb, pinfo, root_tree)

    pinfo.cols.protocol = "RCP-3A";
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

    if startpos > (len - 6) then return startpos end

    local pktlen = bytes:get_index(startpos + 4) * 256 +
                       bytes:get_index(startpos + 5)

    if startpos > (len - (6 + pktlen)) then return startpos end

    local range = tvb:range(startpos, 6 + pktlen)
    processPacket(root_tree, range)
    return startpos, range:len()
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(5001, r_rcp3a)

