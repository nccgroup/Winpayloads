#!/usr/bin/python3
from lib.menu import getAndRunMainMenu
import blessed
import sys
import subprocess
import os


t = blessed.Terminal()


DIR = os.path.expanduser('~') + '/winpayloads'
if not os.path.isdir(DIR):
    os.mkdir(DIR)


try:
    print(t.bold_green + "Checking if up-to-date || ctr + c to cancel" + t.normal)
    gitrev = subprocess.check_output(['git', 'rev-parse', 'HEAD']).rstrip()
    gitlsremote = subprocess.check_output(['git', 'ls-remote', 'origin', 'master']).split()[0]
    if gitrev != gitlsremote:
        updateornah = input(t.bold_red + "Do you want to update WinPayloads? y/[n]: " + t.normal)
        if updateornah.lower() == "y":
            p = subprocess.Popen(['git', 'pull'])
            p.wait()
            print(t.bold_yellow + "Reload Winpayloads..." + t.normal)
            sys.exit()
except subprocess.CalledProcessError:
    print(t.bold_red + "[!] No Connection to Github" + t.normal)
except KeyboardInterrupt:
    pass

try:
    getAndRunMainMenu()
except KeyboardInterrupt:
    print(t.bold_green + '\n[*] Cleaning Up\n' + t.normal)
    subprocess.call(['rm *.rc'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['rm *.ps1'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['rm logdict*'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.exit()
