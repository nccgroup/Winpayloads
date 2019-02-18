#
#   Minimum Registry size checker (default: 55 MB), PowerShell
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	  Edited for use in winpayloads

if ($Args.count -eq 0) {
  $minRegSizeMB = 55
} else {
  $minRegSizeMB = $($args[0])
}

$regSize = GWMI -Class Win32_Registry | Select-Object -Expand CurrentSize

if ($regSize -gt $minRegSizeMB) {
  continue
} else {
  exit
}
