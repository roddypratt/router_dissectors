local test = Proto("Test", "Test dissector");

local f_test = ProtoField.char("Test.Sequence", "Sequence");

test.fields = { f_test };

function test.dissector(tvb, pinfo, root_tree)
    local range = tvb:range(1, 1)

    root_tree:add(f_test, range, range:string())
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(12345, test)
