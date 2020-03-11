Function portsweep {
  param($list,$port) 

  if (!$port) {
    Write-Host "usage: portsweep <list.txt> <port>"
    Write-Host " e.g.: portsweep ips.txt 445`n"
    return
  }
  $results = ".\portsweep.$port.txt"
   
  foreach($line in Get-Content $list) {
    $x = (gc $results -EA SilentlyContinue | select-string "^$line,$port,")
    if ($x) {
      gc $results | select-string "^$line,$port,"
      continue
    }
    $output = "$line,$port,"
   
    $c = new-object system.net.sockets.tcpclient
    $c.SendTimeout = 500
    try {
      $c.Connect($line,$port)
    } catch {}
    if ($c.Connected) {
      $output += "True"
    } else {
      $output += "False"
    }
    Write-Host "$output"
    echo $output >>$results
  }
}
