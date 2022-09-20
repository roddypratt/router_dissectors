-- Grass Valley Native Protocol dissector for Wireshark.
--
-- Copyright (C) 2021-2022 Rascular Technology Ltd.
--------------------------------------------------------------
local gvg = Proto("GVGNative", "Grass Valley Native protocol");

local f_body = ProtoField.string("GVGNative.body", "Body");
local f_stx = ProtoField.uint8("GVGNative.STX", "STX");
local f_native = ProtoField.string("GVGNative.Native", "Native");
local f_sequence = ProtoField.string("GVGNative.Sequence", "Sequence");
local f_command = ProtoField.string("GVGNative.Command", "Command");
local f_params = ProtoField.string("GVGNative.Params", "Params");
local f_param = ProtoField.string("GVGNative.Param", "Param");

local f_checksum = ProtoField.string("GVGNative.Checksum", "Checksum");
local f_eot = ProtoField.uint8("GVGNative.EOT", "EOT");

gvg.fields = { f_body, f_stx, f_native, f_sequence, f_command, f_params, f_param, f_checksum, f_eot };


local ef_bad_checksum = ProtoExpert.new("GVGNative.checksum.expert", "Bad checksum",
    expert.group.CHECKSUM,
    expert.severity.ERROR);

local ef_bad_stx = ProtoExpert.new("GVGNative.stx.expert", "Bad STX",
    expert.group.MALFORMED,
    expert.severity.ERROR);

local ef_bad_protocol = ProtoExpert.new("GVGNative.protocol.expert", "Bad Protocol",
    expert.group.MALFORMED,
    expert.severity.ERROR);

local ef_error = ProtoExpert.new("GVGNative.error.expert", "Error Code",
    expert.group.RESPONSE_CODE,
    expert.severity.ERROR);

gvg.experts = { ef_bad_checksum, ef_bad_stx, ef_bad_protocol, ef_error }

local commands = { AS = "Machine Assign",
    BK = "Background Activities",
    CH = "Request Chop",
    CT = "Clear Tielines",
    DA = "Machine De-assign",
    NY = "Notification",
    PI = "Protect by Index",
    PR = "request Protect",
    QA = "Query Machine Assignment",
    QB = "Query Alarm Definitions",
    QC = "Query COmbined Destination Status",
    QD = "Query Destination Status",
    Qd = "Query Destination status",
    QE = "Query Error Definition",
    QH = "Query Alarm Status",
    QI = "Query Destination by Index",
    Qi = "Query Destination by index",
    QJ = "Query Destination by index",
    Qj = "Query Destination by index",
    QL = "Query Destination with Tieline Info",
    Ql = "Query Destination with Tieline Info",
    QN = "Query Names",
    QT = "Query Date and Time",
    QV = "Query Salvo Status",
    SB = "Subscribe",
    ST = "Set Date and Time",
    TA = "Take",
    TD = "Take Destination",
    TI = "Take Index with Level Index",
    TJ = "Take Index with Level Bitmap",
    TM = "Take Monitor Destination",
    TS = "Take Salvo",
    UI = "Unprotect by Index",
    UB = "Unsubscribe",
    UP = "Unprotect"
}

bk_commands = {
    I = "Refresh Interval",
    N = "Get Device Name",
    R = "Get Software Revision",
    T = "Get software Title",
    t = "Get Protcol",
    F = "Ger reset occurences",
    f = "Mask clear change flags",
    d = "Get Port Name",
    D = "Clear QD Flags",
    A = "Clear QA Flags",
    P = "Get port configuration parameters",
    E = "Get/Set Level 4 Echo",
    ["2"] = "Null Command"
}

error_codes = {
    [0] = "OK",
    [1] = "Directed Response Error",
    [2] = "Unknown Error Code",
    [3] = "System Error",
    [4] = "System Table Error",
    [5] = "Not Implemented",
    [6] = "Semaphore Create Error",
    [7] = "Semaphore Give Error",
    [8] = "Semaphore Take Error",
    [66] = "Unknown Dest Name",
    [67] = "Unknown Source Name",
    [68] = "Unknown Salvo name",
    [69] = "Bad Level Bit Map",
    [70] = "Invalid Control Level",
    [71] = "Panel Locked",
    [72] = "Chop Lock",
    [73] = "Salvo Lock",
    [74] = "No Monitor Control",
    [75] = "Send To MCPU Error",
    [76] = "Redirect CoProc Msgs Err",
    [77] = "Assignments Not Enabled",
    [78] = "New Net Detected, But Not Active",
    [79] = "Previously Detected Net Now Not Active",
    [128] = "Unknown Command",
    [129] = "CL-CMD Disabled",
    [130] = "Bad CL-CMD Syntax",
    [131] = "Bad Nbr of Sources",
    [132] = "BadError Code",
    [133] = "Parse EOT missing",
    [134] = "Parse HT missing",
    [135] = "Parse Bad Protect Flag",
    [136] = "Parse Bad Dst Name",
    [137] = "Parse Bad Src Name",
    [138] = "Too Many Sources",
    [139] = "Bad Parameter",
    [140] = "Bad Mask",
    [141] = "Unknown Tag For RCL2",
    [142] = "Chksum Lvl4 Err",
    [143] = "Lvl4 Embedded SOH Err",
    [144] = "Lvl4 Embedded EOT Err",
    [145] = "Bad Dst Index",
    [146] = "Unknown Dst Index",
    [147] = "Bad Src Index",
    [148] = "Unknown Src Index",
    [149] = "Bad Level Index",
    [150] = "Invalid Ctl Lvl Index",
    [151] = "Level Not In Destination",
    [152] = "Rooms Not Enabled",
    [153] = "Room Count Is Zero",
    [154] = "No Dest Status Exists",
    [155] = "Err Trying To Set Time in MCPU",
    [156] = "Date format error",
    [157] = "Time format error",
    [158] = "Parse Bad Salvo Name",
    [188] = "Unknown Alarm Type",
    [189] = "Invalid Alarm Id",
    [190] = "Invalid Alarm Range",
    [191] = "Invalid Dest Range",
    [192] = "Invalid Command format",
    [193] = "Salvo Excluded",
    [194] = "Invalid Number Of Entries",
    [195] = "Invalid Attribute value",
    [196] = "Bad Number of Entries",
    [197] = "Not Supported",
    [198] = "SNMP Disabled",
    [199] = "Not Supported in WIN32"
}


function rangeByte(range, i)
    local r = range:range(i, 1)
    return r, r:uint()
end

function rangeString(range, i, len)
    local r = range:range(i, len)
    return r, r:string()
end

function rangeChar(range, i)
    local r = range:range(i, 1)
    return r, r:string()
end

function processPacket(mess, root, range)
    local tree = root:add(range, "GVG Native")

    local c = mess[1]
    if c ~= 1 then
        tree:add_proto_expert_info(ef_bad_stx)
    end

    tree:add(f_stx, rangeByte(range, 0))
    local f, s = rangeChar(range, 1)
    tree:add(f_native, f, s)
    if s ~= "N" then
        tree:add_proto_expert_info(ef_bad_protocol)
    end
    tree:add(f_sequence, rangeChar(range, 2))

    f, s = rangeString(range, 3, 2)
    local item = tree:add(f_command, f, s)

    local params = {}

    local r, paramstr = rangeString(range, 6, #mess - 8)
    for token in string.gmatch(paramstr, "[^\t]+") do
        params[#params + 1] = token
    end

    if s == "BK" then
        if bk_commands[params[1]] then
            item:append_text(": " .. bk_commands[params[1]])
        else
            item:append_text(": ", params[1])
        end
    elseif s == "ER" then
        local code = tonumber(params[1], 16)
        item:append_text(": " .. error_codes[code])
        if code ~= 0 then
            item:add_proto_expert_info(ef_error)
        end
    elseif commands[s] then
        item:append_text(": " .. commands[s])
    end

    item = tree:add(f_params, r, paramstr)
    for i, token in ipairs(params) do
        item:add(f_param, token)
    end

    -- validate checksum
    local sum = 0
    for i = 2, #mess - 2 do sum = sum + mess[i] end

    f, s = rangeString(range, #mess - 2, 2)

    tree:add(f_checksum, f, s)

    if bit32.band(-sum, 0xff) ~= tonumber(s, 16) then
        tree:add_proto_expert_info(ef_bad_checksum)
    end

    tree:add(f_eot, rangeByte(range, #mess))

end

function gvg.dissector(tvb, pinfo, root_tree)

    pinfo.cols.protocol = "GVG Native";
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
    local mess = {}

    for p = startpos, len - 1 do
        local c = bytes:get_index(p)
        if c == 4 then -- EOT
            local range = tvb:range(startpos, #mess + 1)
            processPacket(mess, root_tree, range)
            return startpos, #mess + 1
        else
            mess[#mess + 1] = c
        end
    end
    return startpos -- end not found - keep looking
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(12345, gvg)
