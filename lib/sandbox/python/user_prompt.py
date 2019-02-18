#
#   Prompts user with dialog box and waits for response before executing, Python
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	Edited for use in winpayloads

import ctypes
import sys

dialogBoxTitle = "Update Complete";
dialogBoxMessage = "Press OK to Continue"

if len(sys.argv) == 3:
	dialogBoxTitle = sys.argv[1]
	dialogBoxMessage = sys.argv[2]

MessageBox = ctypes.windll.user32.MessageBoxW
MessageBox(None, dialogBoxMessage, dialogBoxTitle, 0)
