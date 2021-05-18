-- ProBel SW-P-08 Protocol dissector for Wireshark.
--
-- Copyright (C) 2021 Rascular Technology Ltd.
--------------------------------------------------------------
local CROSSPOINT_INTERROGATE = 1
local CROSSPOINT_CONNECT = 2
local CROSSPOINT_TALLY = 3
local CROSSPOINT_CONNECTED = 4
local PROTECT_INTERROGATE = 10
local PROTECT_TALLY = 11
local PROTECT_CONNECT = 12
local PROTECT_CONNECTED = 13;
local PROTECT_DISCONNECT = 14
local PROTECT_DISCONNECTED = 15

local CROSSPOINT_TALLY_DUMP_REQUEST = 21
local CROSSPOINT_TALLY_DUMP_RESPONSE_BYTE = 22
local CROSSPOINT_TALLY_DUMP_RESPONSE_WORD = 23

local ALL_SOURCE_NAMES = 100
local ALL_DESTINATION_NAMES = 102
local SOURCE_NAMES_RESPONSE = 106
local DESTINATION_NAMES_RESPONSE = 107

local EXT_CROSSPOINT_INTERROGATE = CROSSPOINT_INTERROGATE + 0x80;
local EXT_CROSSPOINT_CONNECT = CROSSPOINT_CONNECT + 0x80;
local EXT_CROSSPOINT_TALLY = CROSSPOINT_TALLY + 0x80;
local EXT_CROSSPOINT_CONNECTED = CROSSPOINT_CONNECTED + 0x80;

local EXT_PROTECT_INTERROGATE = PROTECT_INTERROGATE + 0x80;
local EXT_PROTECT_TALLY = PROTECT_TALLY + 0x80;
local EXT_PROTECT_CONNECT = PROTECT_CONNECT + 0x80;
local EXT_PROTECT_CONNECTED = PROTECT_CONNECTED + 0x80;
local EXT_PROTECT_DISCONNECT = PROTECT_DISCONNECT + 0x80;
local EXT_PROTECT_DISCONNECTED = PROTECT_DISCONNECTED + 0x80;

local EXT_CROSSPOINT_TALLY_DUMP_REQUEST = CROSSPOINT_TALLY_DUMP_REQUEST + 0x80
local EXT_CROSSPOINT_TALLY_DUMP_RESPONSE =
    CROSSPOINT_TALLY_DUMP_RESPONSE_WORD + 0x80

local codes = {
    [0] = "COMMAND_ENABLE",
    [CROSSPOINT_INTERROGATE] = "CROSSPOINT_INTERROGATE",
    [CROSSPOINT_CONNECT] = "CROSSPOINT_CONNECT",
    [CROSSPOINT_TALLY] = "CROSSPOINT_TALLY",
    [CROSSPOINT_CONNECTED] = "CROSSPOINT_CONNECTED",
    [7] = "MAINTENANCE",
    [8] = "DUAL_CONTROLLER_STATUS",
    [9] = "DUAL_CONTROLLER_STATUS_RESPONSE",
    [PROTECT_INTERROGATE] = "PROTECT_INTERROGATE",
    [PROTECT_TALLY] = "PROTECT_TALLY",
    [PROTECT_CONNECT] = "PROTECT_CONNECT",
    [PROTECT_CONNECTED] = "PROTECT_CONNECTED",
    [PROTECT_DISCONNECT] = "PROTECT_DISCONNECT",
    [PROTECT_DISCONNECTED] = "PROTECT_DISCONNECTED",
    [17] = "PROTECT_DEVICE_NAME_REQUEST",
    [18] = "PROTECT_DEVICE_NAME_RESONSE",
    [19] = "PROTECT_TALLY_DUMP_REQUEST",
    [20] = "PROTECT_TALLY_DUMP_RESPONSE",
    [CROSSPOINT_TALLY_DUMP_REQUEST] = "CROSSPOINT_TALLY_DUMP_REQUEST",
    [CROSSPOINT_TALLY_DUMP_RESPONSE_BYTE] = "CROSSPOINT_TALLY_DUMP_RESPONSE_BYTE",
    [CROSSPOINT_TALLY_DUMP_RESPONSE_WORD] = "CROSSPOINT_TALLY_DUMP_RESPONSE_WORD",

    [25] = "ROUTER_IO_PARAMETERS_INTERROGATE",
    [26] = "ROUTER_IO_PARAMETERS_TALLY",
    [27] = "ROUTER_IO_PARAMETERS_CONNECT",
    [28] = "ROUTER_IO_PARAMETERS_CONNECTED",
    [29] = "MASTER_PROTECT_CONNECT",
    [30] = "NAMES_UPDATED",

    [41] = "DIAGNOSTIC",
    [43] = "DIAGNOSTIC_RESPONSE",
    [44] = "LOG_MESSAGE",

    [76] = "STATUS_CONFIGURATION",
    [77] = "STATUS_CONFIGURATION_TALLY",
    [78] = "LOGGING_STRINGS",
    [79] = "ERROR_STATUS_REQUEST",

    [87] = "SOFT_KEY_TALLY_REQUEST",
    [88] = "SOFT_KEY_TALLY_RESPONSE",
    [89] = "SOFT_KEY_ASSIGNEMENT_SET_REQUEST",
    [90] = "SOFT_KEY_ASSIGNEMENT_SET_RESPONSE",

    [ALL_SOURCE_NAMES] = "ALL_SOURCE_NAMES",
    [101] = "SINGLE_SOURCE_NAME",
    [ALL_DESTINATION_NAMES] = "ALL_DESTINATION_NAMES",
    [103] = "SINGLE_DESTINATION_NAME",
    [104] = "ALL_UMD_LABELS",
    [105] = "SINGLE_UMD_LABEL",
    [SOURCE_NAMES_RESPONSE] = "SOURCE_NAMES_RESONSE",
    [DESTINATION_NAMES_RESPONSE] = "DESTINATION_NAMES_RESPONSE",
    [108] = "UMD_LABELS_RESPONSE",

    [114] = "ALL_SOURCE_ASSOCIATION_NAMES",
    [115] = "SINGLE_SOURCE_ASSOCIATION_NAMES",
    [116] = "SOURCE_ASSOCIATION_NAMES_RESPONSE",
    [117] = "UPDATE_NAME",

    [111] = "CROSSPOINT_TIE_LINE_CONNECT",
    [112] = "CROSSPOINT_TIE_LINE_INTERROGATE",
    [113] = "CROSSPOINT_TIE_LINE_TALLY",

    [120] = "CROSSPOINT_CONNECT_ON_GO_GROUP_SALVO",
    [121] = "CROSSPOINT_GO_GROUP_SALVO",
    [122] = "CROSSPOINT_CONNECT_ON_GO_GROUP_SALVO_ACK",
    [123] = "CROSSPOINT_GO_DONE_GROUP_SALVO",
    [124] = "CROSSPOINT_SALVO_GROUP_INTERROGATE",
    [125] = "CROSSPOINT_GROUP_SALVO_TALLY",

    [EXT_CROSSPOINT_INTERROGATE] = "EXT_CROSSPOINT_INTERROGATE",
    [EXT_CROSSPOINT_CONNECT] = "EXT_CROSSPOINT_CONNECT",
    [EXT_CROSSPOINT_TALLY] = "EXT_CROSSPOINT_TALLY",
    [EXT_CROSSPOINT_CONNECTED] = "EXT_CROSSPOINT_CONNECTED",
    [EXT_PROTECT_INTERROGATE] = "EXT_PROTECT_INTERROGATE",
    [EXT_PROTECT_TALLY] = "EXT_PROTECT_TALLY",
    [EXT_PROTECT_CONNECT] = "EXT_PROTECT_CONNECT",
    [EXT_PROTECT_CONNECTED] = "EXT_PROTECT_CONNECTED",
    [EXT_PROTECT_DISCONNECT] = "EXT_PROTECT_DISCONNECT",
    [EXT_PROTECT_DISCONNECTED] = "EXT_PROTECT_DISCONNECTED",
    [EXT_CROSSPOINT_TALLY_DUMP_RESPONSE] = "EXT_CROSSPOINT_TALLY_DUMP_RESPONSE",

    [0x1006] = "ACK",
    [0x1015] = "NAK"

}

local protcodes = {
    [0] = "Unlocked",
    [1] = "Pro-Bel protect",
    [2] = "Override protect",
    [3] = "OEM Protect"
}

local namelengths = {[0] = 4, [1] = 8, [2] = 12, [3] = 16, [4] = 32}
-- local namelengths = {[0] = "4 char", [1] = "8 char", [2] = "12 char", [3] = "16 char", [4] = "32 char"}

local p_swp08 = Proto("swp08", "Pro-Bel SW-P-08 protocol");
local f_opcode = ProtoField.uint16("swp.op", "OpCode", base.HEX, codes);
local f_matrix4 = ProtoField.uint8("swp.matrix", "Matrix", base.HEX, nil, 0xF0);
local f_matrix8 = ProtoField.uint8("swp.matrix", "Matrix");

local f_level4 = ProtoField.uint8("swp.level", "Level", base.HEX, nil, 0xF);
local f_level8 = ProtoField.uint8("swp.level", "Level");

local f_name = ProtoField.string("swp.name", "Name");

local f_source16 = ProtoField.uint16("swp.source", "Source");
local f_dest16 = ProtoField.uint16("swp.dest", "Dest");
local f_start = ProtoField.uint16("swp.start", "Start");
local f_device = ProtoField.uint16("swp.device", "Device");
local f_checksum = ProtoField.uint8("swp.checksum", "Checksum");
local f_length = ProtoField.uint8("swp.length", "Length");
local f_count = ProtoField.uint8("swp.count", "Count");

local f_namelength = ProtoField.uint8("swp.namelength", "NameLength", base.HEX,
                                      namelengths);
local f_protect =
    ProtoField.uint8("swp.protect", "Protect", base.HEX, protcodes);

p_swp08.fields = {
    f_opcode, f_matrix8, f_level8, f_source16, f_dest16, f_device, f_checksum,
    f_protect, f_length, f_namelength, f_level4, f_matrix4, f_start, f_name,
    f_count
};

local ef_bad_length = ProtoExpert.new("swp.length.expert", "Bad length",
                                      expert.group.MALFORMED,
                                      expert.severity.ERROR);

local ef_bad_checksum = ProtoExpert.new("swp.checksum.expert", "Bad checksum",
                                        expert.group.MALFORMED,
                                        expert.severity.ERROR);
local ef_bad_dle = ProtoExpert.new("swp.baddle.expert", "Bad DLE sequence",
                                   expert.group.MALFORMED, expert.severity.ERROR);

p_swp08.experts = {ef_bad_length, ef_bad_checksum, ef_bad_dle}

local DLE = 0x10
local STX = 2
local ETX = 3
local ACK = 6
local NAK = 0x15

function dLen(s, start, l)
    local dl = l
    local ds = 0
    for i = 1, start - 1 do if s[i] == DLE then ds = ds + 1 end end
    for i = 0, l - 1 do if s[i + start] == DLE then dl = dl + 1 end end
    return start + ds + 2 - 1, dl
end

function rangeByte(range, mess, i) return range:range(dLen(mess, i, 1)), mess[i] end
function rangeWord(range, mess, i)
    return range:range(dLen(mess, i, 2)), mess[i] * 256 + mess[i + 1]
end

function rangeString(range, mess, i, len)
    local r = range:range(dLen(mess, i, len))
    return r, "\"" .. r:string() .. "\""
end

function rangeDest12(range, mess, i)
    return range:range(dLen(mess, i, 2)), bit32.lshift(
               bit32.band(0x7, bit32.rshift(mess[i], 4)), 7) + mess[i + 1]
end
function rangeSrc12(range, mess, i)
    return range:range(dLen(mess, i, 3)),
           bit32.lshift(bit32.band(mess[i], 0xf), 7) + mess[i + 2]
end

function processPacket(mess, root, range)
    local tree = root:add(range, "SW-P-08")
    local op = mess[1]

    tree:add(f_opcode, rangeByte(range, mess, 1))

    if op == CROSSPOINT_INTERROGATE or op == PROTECT_INTERROGATE then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_level4, rangeByte(range, mess, 2))
        tree:add(f_dest16, rangeDest12(range, mess, 3))
    elseif op == CROSSPOINT_CONNECT or op == CROSSPOINT_CONNECTED or op ==
        CROSSPOINT_TALLY then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_level4, rangeByte(range, mess, 2))
        tree:add(f_dest16, rangeDest12(range, mess, 3))
        tree:add(f_source16, rangeSrc12(range, mess, 3))
    elseif op == PROTECT_CONNECT or op == PROTECT_DISCONNECT then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_level4, rangeByte(range, mess, 2))
        tree:add(f_device, rangeByte(range, mess, 5))
    elseif op == EXT_CROSSPOINT_INTERROGATE or op == EXT_PROTECT_INTERROGATE then
        tree:add(f_matrix8, rangeByte(range, mess, 2))
        tree:add(f_level8, rangeByte(range, mess, 3))
        tree:add(f_dest16, rangeWord(range, mess, 4))
    elseif op == PROTECT_TALLY or op == PROTECT_DISCONNECTED or op ==
        PROTECT_CONNECTED then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_level4, rangeByte(range, mess, 2))
        tree:add(f_protect, rangeByte(range, mess, 3))
        tree:add(f_dest16, rangeDest12(range, mess, 4))
    elseif op == EXT_CROSSPOINT_CONNECT or op == EXT_CROSSPOINT_CONNECTED or op ==
        EXT_CROSSPOINT_TALLY then
        tree:add(f_matrix8, rangeByte(range, mess, 2))
        tree:add(f_level8, rangeByte(range, mess, 3))
        tree:add(f_dest16, rangeWord(range, mess, 4))
        tree:add(f_source16, rangeWord(range, mess, 6))
    elseif op == EXT_PROTECT_CONNECT or op == EXT_PROTECT_DISCONNECT then
        tree:add(f_matrix8, rangeByte(range, mess, 2))
        tree:add(f_level8, rangeByte(range, mess, 3))
        tree:add(f_dest16, rangeWord(range, mess, 4))
        tree:add(f_device, rangeWord(range, mess, 6))
    elseif op == EXT_PROTECT_TALLY or op == EXT_PROTECT_DISCONNECTED or op ==
        EXT_PROTECT_CONNECTED then
        tree:add(f_matrix8, rangeByte(range, mess, 2))
        tree:add(f_level8, rangeByte(range, mess, 3))
        tree:add(f_protect, rangeByte(range, mess, 4))
        tree:add(f_dest16, rangeWord(range, mess, 5))
        tree:add(f_device, rangeWord(range, mess, 7))
    elseif op == SOURCE_NAMES_RESPONSE or op == DESTINATION_NAMES_RESPONSE then
        tree:add(f_matrix8, rangeByte(range, mess, 2))
        tree:add(f_namelength, rangeByte(range, mess, 3))
        tree:add(f_start, rangeWord(range, mess, 4))
        tree:add(f_count, rangeByte(range, mess, 6))
        local count = mess[6]

        local l = namelengths[mess[3]];

        for i = 0, count - 1 do
            tree:add(f_name, rangeString(range, mess, 7 + (i * l), l))
        end
    elseif op == ALL_SOURCE_NAMES or op == ALL_DESTINATION_NAMES then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_namelength, rangeByte(range, mess, 3))
    elseif op == CROSSPOINT_TALLY_DUMP_REQUEST then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_level4, rangeByte(range, mess, 2))
    elseif op == CROSSPOINT_TALLY_DUMP_RESPONSE_WORD then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_level4, rangeByte(range, mess, 2))
        tree:add(f_count, rangeByte(range, mess, 3))
        tree:add(f_dest16, rangeWord(range, mess, 4))
        local count = mess[3]
        for i = 0, count - 1 do
            tree:add(f_source16, rangeWord(range, mess, 6 + i * 2))
        end
    elseif op == CROSSPOINT_TALLY_DUMP_RESPONSE_BYTE then
        tree:add(f_matrix4, rangeByte(range, mess, 2))
        tree:add(f_level4, rangeByte(range, mess, 2))
        tree:add(f_count, rangeByte(range, mess, 3))
        tree:add(f_dest16, rangeByte(range, mess, 4))
        local count = mess[3]
        for i = 0, count - 1 do
            tree:add(f_source16, rangeByte(range, mess, 5 + i))
        end
    elseif op == EXT_CROSSPOINT_TALLY_DUMP_REQUEST then
        tree:add(f_matrix8, rangeByte(range, mess, 2))
        tree:add(f_level8, rangeByte(range, mess, 3))
    elseif op == EXT_CROSSPOINT_TALLY_DUMP_RESPONSE then
        tree:add(f_matrix8, rangeByte(range, mess, 2))
        tree:add(f_level8, rangeByte(range, mess, 3))
        tree:add(f_count, rangeByte(range, mess, 4))
        tree:add(f_dest16, rangeWord(range, mess, 5))
        local count = mess[3]
        for i = 0, count - 1 do
            tree:add(f_source16, rangeWord(range, mess, 7 + i * 2))
        end
    end

    tree:add(f_length, rangeByte(range, mess, #mess - 1))
    if (#mess - 2) ~= mess[#mess - 1] then
        tree:add_proto_expert_info(ef_bad_length)
    end

    -- validate checksum
    local sum = 0
    for i = 1, #mess - 1, 1 do sum = sum + mess[i] end

    if bit32.band(-sum, 0xff) ~= mess[#mess] then
        tree:add_proto_expert_info(ef_bad_checksum)

    end
    tree:add(f_checksum, rangeByte(range, mess, #mess))
end

function processACK(root, range) root:add(f_opcode, range) end
function processNAK(root, range) root:add(f_opcode, range) end

function p_swp08.dissector(tvb, pinfo, root_tree)

    pinfo.cols.protocol = "SW-P-08";
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
        if (bytes:get_index(p) == DLE) and (p + 1 < len) and
            (bytes:get_index(p + 1) == ACK) then
            processACK(root_tree, tvb:range(p, 2))
            return p, 2;
        elseif (bytes:get_index(p) == DLE) and (p + 1 < len) and
            (bytes:get_index(p + 1) == NAK) then
            processNAK(root_tree, tvb:range(p, 2))
            return p, 2;
        elseif (bytes:get_index(p) == DLE) and (p + 1 < len) and
            (bytes:get_index(p + 1) == STX) then
            start = p
            -- print("Found start ", start)
            p = p + 2
            local mess = {}
            while p < len do
                local c = bytes:get_index(p)
                p = p + 1
                if c ~= DLE then
                    mess[#mess + 1] = c
                else
                    if p < len then
                        c = bytes:get_index(p)
                        p = p + 1
                        if c == DLE then
                            mess[#mess + 1] = c
                        elseif c == ETX then
                            local range = tvb:range(start, p - start)
                            processPacket(mess, root_tree, range)
                            return start, p - start
                        else
                            root_tree:add_proto_expert_info(ef_bad_dle)
                            print("Bad DLE, Returning ", p)
                            return start, p
                        end
                    end
                end
            end
        end
        p = p + 1
    end

    return p -- packet is segmented or no start found.
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(2007, p_swp08)
tcp_encap_table:add(2008, p_swp08)

