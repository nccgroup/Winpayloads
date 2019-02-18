#
#   Minimum disk size checker (default: 50 GB), PowerShell
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	  Edited for use in winpayloads

if ($Args.count -eq 0) {
  $minDiskSizeGB = 50
} else {
  $minDiskSizeGB = $($args[0])
}

$diskSizeGB = (GWMI -Class Win32_LogicalDisk | Measure-Object -Sum Size | Select-Object -Expand Sum) / 1073741824

if ($diskSizeGB -gt $minDiskSizeGB) {
  continue
} else {
  exit
}
