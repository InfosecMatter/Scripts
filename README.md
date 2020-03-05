# Scripts

**firebird-bruteforce.sh**
```
# Usage:
firebird-bruteforce.sh <IP> <username> <wordlist.txt>

# Example:
firebird-bruteforce.sh 10.1.10.101 SYSDBA pwdlist.txt
```

**portsweep.ps1**

A simple port sweeper, which scans list of hosts for an open port.

It retains results in a file in the current working directory, so it can be interrupted and resumed (it will not scan already scanned hosts again).

```
Import-Module .\portsweep.ps1

# Usage:
portsweep <list.txt> <port>

# Example:
portsweep ips.txt 445

# Check results (find open ports):
gc portsweep.*.txt | select-string True
```

**smblogin.ps1**

A simple SMB login attack tool for Active Directory. It takes list of usernames and a password and tries to login with it against specified AD domain.

It retains results in a file in the current working directory, so it can be interrupted and resumed (it will not try to login again if the given user has already been compromised or tried with the given password)

```
Import-Module .\smblogin.ps1

# Usage:
smblogin <userlist.txt> <domain> <password>

# Example:
smblogin users.txt domain.com P@ssw0rd

# Check results (find valid credentials):
gc smblogin.*.txt | select-string True
```
