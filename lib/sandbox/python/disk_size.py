#
#   Minimum disk size checker (default: 50 GB), Python
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	Edited for use in winpayloads

import win32api
import sys

*minDiskSizeGB* = $50$


_, diskSizeBytes, _ = win32api.GetDiskFreeSpaceEx()

diskSizeGB = diskSizeBytes/1073741824

if diskSizeGB > minDiskSizeGB:
    pass
else:
    sys.exit()
