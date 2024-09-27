-- ProBel SW-P-02 Protocol dissector for Wireshark.
--
-- Copyright (C) 2021 Rascular Technology Ltd.
--------------------------------------------------------------
local INTERROGATE = 1
local CONNECT = 2
local TALLY = 3
local CONNECTED = 4
local CONNECT_ON_GO = 5
local GO = 6
local STATUS_REQUEST = 7
local STATUS_RESPONSE_1 = 8
local STATUS_RESPONSE_2 = 9
local STATUS_RESPONSE_3 = 10
local CONNECT_ON_GO_ACK = 12
local GO_DONE_ACK = 13

local EXTENDED_INTERROGATE = 65
local EXTENDED_CONNECT = 66
local EXTENDED_TALLY = 67
local EXTENDED_CONNECTED = 68
local EXTENDED_CONNECT_ON_GO = 69
local EXTENDED_CONNECT_ON_GO_ACK = 70

local ROUTER_CONFIGURATION_REQUEST = 75
local ROUTER_CONFIGURATION_RESPONSE_1 = 76
local ROUTER_CONFIGURATION_RESPONSE_2 = 77

local codes = {
    [0] = "DATABASE CHECKSUM",
    [INTERROGATE] = "INTERROGATE",
    [CONNECT] = "CONNECT",
    [TALLY] = "TALLY",
    [CONNECTED] = "CONNECTED",
    [CONNECT_ON_GO] = "CONNECT_ON_GO",
    [GO] = "GO",
    [STATUS_REQUEST] = "STATUS_REQUEST",
    [STATUS_RESPONSE_1] = "STATUS_RESPONSE_1",
    [STATUS_RESPONSE_2] = "STATUS_RESPONSE_2",
    [STATUS_RESPONSE_3] = "STATUS_RESPONSE_3",

    [CONNECT_ON_GO_ACK] = "CONNECT_ON_GO_ACK",
    [GO_DONE_ACK] = "GO_DONE_ACK",
    [EXTENDED_INTERROGATE] = "EXTENDED_INTERROGATE",
    [EXTENDED_CONNECT] = "EXTENDED_CONNECT",
    [EXTENDED_TALLY] = "EXTENDED_TALLY",
    [EXTENDED_CONNECTED] = "EXTENDED_CONNECTED",
    [EXTENDED_CONNECT_ON_GO] = "EXTENDED_CONNECT_ON_GO",
    [EXTENDED_CONNECT_ON_GO_ACK] = "EXTENDED_CONNECT_ON_GO_ACK",
    [ROUTER_CONFIGURATION_REQUEST] = "ROUTER_CONFIGURATION_REQUEST",
    [ROUTER_CONFIGURATION_RESPONSE_1] = "ROUTER_CONFIGURATION_RESPONSE_1",
    [ROUTER_CONFIGURATION_RESPONSE_2] = "ROUTER_CONFIGURATION_RESPONSE_2"

}

local lengths = {
    [INTERROGATE] = 2,
    [CONNECT] = 3,
    [TALLY] = 3,
    [CONNECTED] = 3,
    [CONNECT_ON_GO] = 3,
    [CONNECT_ON_GO_ACK] = 3,

    [GO] = 1,
    [GO_DONE_ACK] = 1,

    [STATUS_REQUEST] = 1,

    [STATUS_RESPONSE_1] = 3,
    [STATUS_RESPONSE_2] = 1,
    [STATUS_RESPONSE_3] = 3,

    [EXTENDED_INTERROGATE] = 2,
    [EXTENDED_CONNECT] = 4,
    [EXTENDED_TALLY] = 5,
    [EXTENDED_CONNECTED] = 5,

    [EXTENDED_CONNECT_ON_GO] = 4,
    [EXTENDED_CONNECT_ON_GO_ACK] = 4,

    [ROUTER_CONFIGURATION_REQUEST] = 0,
    [ROUTER_CONFIGURATION_RESPONSE_1] = 8,
    [ROUTER_CONFIGURATION_RESPONSE_2] = 14
}

local p_swp02 = Proto("swp02", "Pro-Bel SW-P-02 protocol");
local f_opcode = ProtoField.uint16("swp.op", "OpCode", base.HEX, codes);

local f_name = ProtoField.string("swp.name", "Name");

local f_source = ProtoField.uint16("swp.source", "Source");
local f_dest = ProtoField.uint16("swp.dest", "Dest");

local f_sources = ProtoField.uint16("swp.sources", "Sources");
local f_dests = ProtoField.uint16("swp.dests", "Dests");

local f_start = ProtoField.uint16("swp.start", "Start");
local f_device = ProtoField.uint16("swp.device", "Device");
local f_checksum = ProtoField.uint8("swp.checksum", "Checksum");
local f_status = ProtoField.uint8("swp.status", "Status");

local f_go = ProtoField.uint8("swp.go", "Go", base.HEX,
    { "Set", "Clear", "None Selected" })
local f_count = ProtoField.uint8("swp.count", "Count");

p_swp02.fields = {
    f_opcode, f_source, f_dest, f_device, f_checksum, f_sources, f_dests,
    f_start, f_name, f_count, f_go, f_status
};

local ef_bad_checksum = ProtoExpert.new("swp.checksum.expert", "Bad checksum",
    expert.group.MALFORMED,
    expert.severity.ERROR);

p_swp02.experts = { ef_bad_checksum }

local SOM = 0xFF

function rangeByte(range, i)
    local r = range:range(i, 1)
    return r, r:uint()
end

function rangeWord14(range, i)
    local r = range:range(i, 2)
    local buff = r:bytes()
    return r, bit.lshift(buff:get_index(0), 7) + buff:get_index(1)
end

function rangeDest10(range, i)
    local r = range:range(i, 2)
    local buff = r:bytes()
    return r, bit.lshift(bit.band(buff:get_index(0), 0x70), 3) +
        buff:get_index(1)
end

function rangeSrc10(range, i)
    local r = range:range(i, 3)
    local buff = r:bytes()
    return r, bit.lshift(bit.band(buff:get_index(0), 0x7), 7) +
        buff:get_index(2)
end

function processPacket(root, range)
    local tree = root:add(range, "SW-P-02")
    local r, op = rangeByte(range, 1)

    tree:add(f_opcode, r, op)

    if op == INTERROGATE then
        tree:add(f_dest, rangeDest10(range, 2))
    elseif op == EXTENDED_INTERROGATE then
        tree:add(f_dest, rangeWord14(range, 2))
    elseif op == EXTENDED_CONNECT then
        tree:add(f_dest, rangeWord14(range, 2))
        tree:add(f_source, rangeWord14(range, 4))
    elseif op == EXTENDED_CONNECTED or op == EXTENDED_TALLY then
        tree:add(f_dest, rangeWord14(range, 2))
        tree:add(f_source, rangeWord14(range, 4))
        tree:add(f_status, rangeByte(range, 6))
    elseif (op == CONNECT) or (op == TALLY) or (op == CONNECTED) or
        (op == CONNECT_ON_GO) or (op == CONNECT_ON_GO_ACK) then
        tree:add(f_dest, rangeDest10(range, 2))
        tree:add(f_source, rangeSrc10(range, 2))
    elseif op == GO or op == GO_DONE_ACK then
        tree:add(f_go, rangeByte(range, 2))
    elseif op == ROUTER_CONFIGURATION_RESPONSE_1 then
        tree:add(f_dests, rangeWord14(range, 6))
        tree:add(f_sources, rangeWord14(range, 8))
    end

    -- validate checksum
    local mess = range:bytes()
    local sum = 0
    for i = 1, mess:len() - 2 do sum = sum + mess:get_index(i) end

    if bit.band(-sum, 0x7f) ~= mess:get_index(mess:len() - 1) then
        tree:add_proto_expert_info(ef_bad_checksum)
    end
    tree:add(f_checksum, rangeByte(range, mess:len() - 1))
end

function p_swp02.dissector(tvb, pinfo, root_tree)
    pinfo.cols.protocol = "SW-P-02";
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
    local p = startpos
    local start = 0

    while p < (len - 1) do
        if (bytes:get_index(p) == SOM) and ((p + 1) < len) then
            start = p

            local cmd = bytes:get_index(p + 1) -- command byte found
            if lengths[cmd] and ((p + 2 + lengths[cmd]) < len) then
                local range = tvb:range(start, 3 + lengths[cmd])
                processPacket(root_tree, range)
                return start, range:len()
            end
        end
        p = p + 1
    end

    return p -- packet is segmented or no start found.
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(2006, p_swp02)
