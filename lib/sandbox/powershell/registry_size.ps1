#
#   Minimum Registry size checker (default: 55 MB), PowerShell
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	  Edited for use in winpayloads

*$minRegSizeMB* = $55$

$regSize = GWMI -Class Win32_Registry | Select-Object -Expand CurrentSize

if ($regSize -gt $minRegSizeMB) {
  $a = 1
} else {
  exit
}
