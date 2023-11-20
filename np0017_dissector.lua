-- Nevion MRP Protocol dissector for Wireshark.
--
-- Copyright (C) 2023 Rascular Technology Ltd.
--------------------------------------------------------------
local np0017 = Proto("np0017", "NVision NP-0017 protocol");

local TAKE = 0x3000
local TAKEPORT = 0x3001
local LOCK = 0x3002
local LOCKPORT = 0x3003
local REGISTER = 0x3004
local REGISTERPORT = 0x3005
local GETSTATUS = 0x3006
local GETSTATUSPORT = 0x3007
local LOCKSTATUS = 0x3008
local LOCKSTATUSPORT = 0x3009
local FIRESALVO = 0x300A
local STATUSCHANGED = 0x300B
local STATUSCHANGEDPORT = 0x300C
local GETMNEMONICS = 0x3012
local FINDMNEMONICS = 0x3013
local GETDIMENSIONS = 0x3014
local GETMNEMONICSPORT = 0x3015
local ALLLEVELESTAKE = 0x3016

local GETEXTMNEMONICS = 0x3022
local FINDEXTMNEMONICS = 0x3033
local GETEXTMNEMONICSPORT = 0x3025

local commands = {
    [TAKE] = "TAKE DEVICE",
    [TAKEPORT] = "TAKE PORT",
    [LOCK] = "LOCK/PROTECT DEVICE",
    [LOCKPORT] = "LOCK/PROTECT PORT",
    [REGISTER] = "REGISTER FOR CHANGES",
    [REGISTERPORT] = "REGISTER FOR PORT CHANGES",
    [GETSTATUS] = "GET DEVICE SFTATUS",
    [GETSTATUSPORT] = "GET PORT STATUS",
    [LOCKSTATUS] = "GET DEVICE LOCK STATUS",
    [LOCKSTATUSPORT] = "GET PORT LOCK STATUS",
    [FIRESALVO] = "FIRE SALVO",
    [STATUSCHANGED] = "DEVICE STATUS CHANGED",
    [STATUSCHANGEDPORT] = "PORT STATUS CHANGED",
    [GETMNEMONICS] = "GET DEVICE MNEMONICS",
    [FINDMNEMONICS] = "FIND DEVICE MNEMONIC",
    [GETDIMENSIONS] = "GET DIMENSIONS",
    [GETMNEMONICSPORT] = "GET PORT MNEMONICS",
    [ALLLEVELESTAKE] = "DEVICE TAKE - ALL LEVELS",
    [GETEXTMNEMONICS] = "GET EXTENDED DEVICE MNEMONICS",
    [FINDEXTMNEMONICS] = "FIND EXTENDED DEVICE MNEMONICS",
    [GETEXTMNEMONICSPORT] = "GET EXTENDED PORT MNEMONICS"
}


local lockops = {
    [0] = "Lock Output",
    [1] = "Lock Input",
    [2] = "Protect Output",
    [3] = "Protect Input",
    [4] = "Release Output",
    [5] = "Release Input",
    [6] = "Force Release Output",
    [7] = "Force Release Input"
}

local mnemonictype = {
    [0] = "Device",
    [1] = "Virtual Level",
    [2] = "Sources",
    [3] = "Destinations",
    [4] = "Categories",
    [5] = "Salvos",
    [6] = "Source Categories",
    [7] = "Destination Categories"
}

local f_command = ProtoField.uint32("np0017.command", "Command", base.HEX, commands);
local f_length = ProtoField.uint32("np0017.length", "Length");
local f_sequence = ProtoField.uint32("np0017.sequence", "Sequence");
local f_cmdreply = ProtoField.uint32("np0017.cmdreply", "Cmd/Reply", base.HEX,
    { [0] = "Command", [0x80000000] = "Reply" });
local f_protocol = ProtoField.uint32("np0017.protocol", "Protocol", base.HEX);
local f_input = ProtoField.uint32("np0017.input", "Input");
local f_level = ProtoField.uint32("np0017.level", "Level");
local f_output = ProtoField.uint32("np0017.output", "Output");
local f_userid = ProtoField.uint32("np0017.userid", "User ID");
local f_numentries = ProtoField.uint32("np0017.entries", "Entries");
local f_lockop = ProtoField.uint32("np0017.lockop", "Lock Operation", base.HEX, lockops);
local f_mnemonic = ProtoField.string("np0017.mnemonic", "Mnemonic");

local f_mnemonictype = ProtoField.uint32("np0017.mnemomictype", "Mnemonic Type", base.HEX, mnemonictype);
np0017.fields = { f_command, f_length, f_sequence, f_protocol, f_cmdreply, f_input, f_output, f_level, f_userid,
    f_numentries, f_lockop, f_mnemonictype, f_mnemonic };


local ef_malformed = ProtoExpert.new("np0017.malformed.expert", "Malformed packet",
    expert.group.MALFORMED,
    expert.severity.ERROR);

np0017.experts = { ef_malformed }

function rangeLong(rr, i)
    local r = rr:range(i, 4)
    return r, r:uint()
end

function rangeString(range, i, len)
    local r = range:range(i, len)
    return r, r:string()
end

function add_takeport(tree, range)
    tree:add(f_userid, rangeLong(range, 16))

    local f, n = rangeLong(range, 20)
    tree:add(f_numentries, f, n)

    for i = 1, n do
        local base = 24 + (i - 1) * 16
        local sub = tree:add(range:range(base, 16), "Entry " .. i)
        sub:add(f_input, rangeLong(range, base))
        sub:add(f_level, rangeLong(range, base + 4))
        sub:add(f_output, rangeLong(range, base + 8))
    end
end

function add_lockport(tree, range)
    tree:add(f_userid, rangeLong(range, 16))

    local f, n = rangeLong(range, 20)
    tree:add(f_numentries, f, n)

    for i = 1, n do
        local base = 24 + (i - 1) * 12
        local sub = tree:add(range:range(base, 16), "Entry " .. i)
        sub:add(f_lockop, rangeLong(range, base))
        sub:add(f_level, rangeLong(range, base + 4))
        sub:add(f_output, rangeLong(range, base + 8))
    end
end

function add_dimensions(tree, range)
    -- tree:add(rangeLong(range, 16))
    local f, n = rangeLong(range, 20)
    tree:add(f_numentries, f, n)

    for i = 1, n do
        local base = 24 + (i - 1) * 12
        local sub = tree:add(range:range(base, 16), "Entry " .. i)
        sub:add(f_level, rangeLong(range, base))
        local r1, r2 = rangeLong(range, base + 4)
        sub:add(r1, "Level Type:", r2)
        r1, r2 = rangeLong(range, base + 8)
        sub:add(r1, "Input Start:", r2)
        r1, r2 = rangeLong(range, base + 12)
        sub:add(r1, "Input End:", r2)
        r1, r2 = rangeLong(range, base + 16)
        sub:add(r1, "Output Start:", r2)
        r1, r2 = rangeLong(range, base + 20)
        sub:add(r1, "Output End:", r2)
    end
end

function add_getextmnemonics(tree, range)
    tree:add(f_mnemonictype, rangeLong(range, 16))
    local f, n = rangeLong(range, 20)
    tree:add(f_numentries, f, n)

    for i = 1, n do
        local base = 24 + (i - 1) * 12
        local sub = tree:add(range:range(base, 12), "Entry " .. i)
        sub:add(f_level, rangeLong(range, base))
        sub:add(f_input, rangeLong(range, base + 4))
        local r, v = rangeLong(range, base + 8)
        if v == 0 then
            sub:add(r, "Output port")
        else
            sub:add(r, "Input port")
        end
    end
end

function add_getextmnemonics_reply(tree, range)
    tree:add(f_mnemonictype, rangeLong(range, 20))
    local f, n = rangeLong(range, 24)
    tree:add(f_numentries, f, n)

    local base = 28
    for i = 1, n do
        local lenr, lenv = rangeLong(range, base + 16)
        local sub = tree:add(range:range(base, 20 + lenv), "Entry " .. i)

        sub:add(f_level, rangeLong(range, base))
        sub:add(f_input, rangeLong(range, base + 4))
        local r, v = rangeLong(range, base + 8)
        if v == 0 then
            sub:add(r, "Output port")
        else
            sub:add(r, "Input port")
        end

        sub:add(f_mnemonic, rangeString(range, base + 20, lenv))
        base = base + 20 + lenv
    end
end

function processPacket(root, range)
    local tree = root:add(range, "NP0017")

    tree:add(f_protocol, rangeLong(range, 0))
    tree:add(f_sequence, rangeLong(range, 4))
    tree:add(f_length, rangeLong(range, 8))
    local r, c = rangeLong(range, 12)
    tree:add(f_command, r, bit.band(c, 0x0000FFFF))
    tree:add(f_cmdreply, r, bit.band(c, 0x80000000))

    if c == TAKEPORT then
        add_takeport(tree, range)
    elseif c == LOCKPORT then
        add_lockport(tree, range)
    elseif c == (GETDIMENSIONS + 0x80000000) then
        add_dimensions(tree, range)
    elseif c == GETEXTMNEMONICSPORT then
        add_getextmnemonics(tree, range)
    elseif (c == GETEXTMNEMONICSPORT + 0x80000000) then
        add_getextmnemonics_reply(tree, range)
    end
end

function np0017.dissector(tvb, pinfo, root_tree)
    pinfo.cols.protocol = "NVision NP0017";
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

    if (len < 16) then return startpos end -- 16 byte header

    if (bytes:int(startpos, 4) ~= 0x0e) then
        root_tree:add_tvb_expert_info(ef_malformed, tvb(startpos, 4), "invalid protocol")
        return startpos + 4
    end

    local plen = bytes:int(startpos + 8, 4)

    if plen < 16 or plen > 8192 then
        root_tree:add_tvb_expert_info(ef_malformed, tvb(startpos, 4), "invalid protocol")
        return startpos + 12
    end

    if (len >= plen) then
        processPacket(root_tree, tvb:range(startpos, plen))
        return startpos, plen
    else
        return startpos -- end not found - keep looking
    end
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(9193, np0017)
