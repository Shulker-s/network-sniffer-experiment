local p = Proto("ucasdemo", "UCAS Demo Protocol")
local f_magic = ProtoField.string("ucasdemo.magic", "Magic")
local f_version = ProtoField.uint8("ucasdemo.version", "Version", base.DEC)
local f_type = ProtoField.uint8("ucasdemo.type", "Type", base.DEC)
local f_length = ProtoField.uint32("ucasdemo.length", "Payload length", base.DEC)
local f_payload = ProtoField.string("ucasdemo.payload", "Payload")
p.fields = {f_magic, f_version, f_type, f_length, f_payload}
function p.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "UCASDEMO"
    local offset = 0
    while offset < tvb:len() do
        local remaining = tvb:len() - offset
        if remaining < 8 then pinfo.desegment_offset = offset; pinfo.desegment_len = 8 - remaining; return end
        if tvb(offset,2):string() ~= "NS" then return 0 end
        local length = tvb(offset+4,4):uint()
        if length > 1048576 then
            local node = tree:add(p, tvb(offset,8), "UCAS Demo: invalid length")
            node:add_expert_info(PI_MALFORMED, PI_ERROR, "Payload length exceeds 1 MiB")
            return
        end
        local size = 8 + length
        if remaining < size then pinfo.desegment_offset = offset; pinfo.desegment_len = size - remaining; return end
        local node = tree:add(p, tvb(offset,size))
        node:add(f_magic,tvb(offset,2)); node:add(f_version,tvb(offset+2,1)); node:add(f_type,tvb(offset+3,1)); node:add(f_length,tvb(offset+4,4)); node:add(f_payload,tvb(offset+8,length))
        offset = offset + size
    end
end
DissectorTable.get("tcp.port"):add(19090,p)
