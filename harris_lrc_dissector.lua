-- Harris LRC Protocol dissector for Wireshark.
--
-- Copyright (C) 2021 Rascular Technology Ltd.
--------------------------------------------------------------
local codes = { [0] = "COMMAND_ENABLE" }

local lrc = Proto("lrc", "Harris LRC protocol");

local ops = {
    [string.byte('?')] = "Query",
    [string.byte(':')] = "Command",
    [string.byte('!')] = "Notification",
    [string.byte('%')] = "Response"
}

local types = {
    [string.byte('#')] = "Numeric",
    [string.byte('$')] = "String",
    [string.byte('&')] = "UTF-8",
}

local f_operator = ProtoField.uint8("lrc.operator", "Operator", base.HEX, ops);
local f_type = ProtoField.string("lrc.type", "Type");
local f_arg = ProtoField.string("lrc.arg", "Arg");
local f_argname = ProtoField.string("lrc.argname", "Argument Name");
local f_argtype = ProtoField.char("lrc.argtype", "Type", base.HEX, types);
local f_argvalue = ProtoField.string("lrc.argvalue", "Value");


lrc.fields = { f_type, f_operator, f_arg, f_argname, f_argtype, f_argvalue };

local ef_malformed = ProtoExpert.new("lrc.malformed.expert", "Malformed packet",
    expert.group.MALFORMED,
    expert.severity.ERROR);
local ef_badargtype = ProtoExpert.new("lrc.badargtype.expert", "Bad argument type",
    expert.group.MALFORMED,
    expert.severity.ERROR);

lrc.experts = { ef_malformed, ef_badargtype }

function rangeChar(range, i)
    local r = range:range(i, 1)
    return r, r:uint()
end

function rangeString(range, i, len)
    local r = range:range(i, len)
    return r, r:string()
end

function addArg(tree, range)
    local t = tree:add(f_arg, range)
    -- look for { character, then split off name and previous char
    local s = range:string()
    local p = s:find("{")
    if p then
        local argType = s:sub(p - 1, p - 1)
        t:add(f_argname, range:range(0, p - 2))
        t:add(f_argtype, range:range(p - 2, 1))

        if (argType ~= '#' and argType ~= '$' and argType ~= '&') then
            tree:add_tvb_expert_info(ef_badargtype, range:range(p - 2, 1),
                "Unknown argument type" .. argType)
        end
        range = range:range(p, #s - (p + 1))
        -- split range on commas, and add as list of values
        local ss = range:string()
        local a = 1
        for p in ss:gmatch("()%,") do
            t:add(f_argvalue, range:range(a - 1, p - a))
            a = p + 1
        end
        if a <= #ss then
            t:add(f_argvalue, range:range(a - 1, #ss - a + 1))
        end
    else
        tree:add_tvb_expert_info(ef_badargtype, range,
            "Argument missing name")
    end
end

function processPacket(mess, root, range)
    local tree = root:add(range, "Harris LRC")

    local a
    for p = 2, #mess do
        if ops[mess[p]] then
            tree:add(f_type, rangeString(range, 1, p - 1))
            tree:add(f_operator, rangeChar(range, p))
            a = p + 1
            break
        end
    end

    for p = a, #mess do
        if mess[p] == string.byte(';') then
            addArg(tree, rangeString(range, a, p - a))
            a = p + 1
        end
    end

    if #mess > a then addArg(tree, rangeString(range, a, 1 + #mess - a)) end
end

function lrc.dissector(tvb, pinfo, root_tree)
    pinfo.cols.protocol = "Harris LRC";
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
    local start = startpos
    local startFound = false
    local mess = {}
    for p = startpos, len - 1 do
        local c = bytes:get_index(p)
        if (c == string.byte('~')) then
            if startFound or (#mess > 0) then
                root_tree:add_tvb_expert_info(ef_malformed,
                    tvb(start, p - start),
                    "Junk before start")
            end
            start = p
            startFound = true
            mess = {}
        elseif c == string.byte('\\') then
            if startFound then
                local range = tvb:range(start, 1 + p - start)
                processPacket(mess, root_tree, range)
                return start, 1 + p - start
            else
                root_tree:add_tvb_expert_info(ef_malformed,
                    tvb(start, 1 + p - start),
                    "End without start")
                return start, 1 + p - start
            end
        else
            mess[#mess + 1] = c
        end
    end

    if start >= 0 then
        return start         -- packet is incomplete
    else
        return startpos, len -- no start found, discard
    end
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(52116, lrc)
