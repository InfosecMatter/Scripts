# Scripts

**firebird-bruteforce.sh**

```
# Usage:
firebird-bruteforce.sh <IP> <username> <wordlist.txt>

# Example:
firebird-bruteforce.sh 10.1.10.101 SYSDBA pwdlist.txt
```

More information here: https://www.infosecmatter.com/firebird-database-exploitation/

---

**yanp.sh**

Yet Another Nessus Parser.

It will take every Nessus CSV report found in the current working directory and it will parse out the following information from each CSV report:

- List of found IP addresses
- List of resolved hostnames and corresponding IP addresses
- List of open TCP and UDP ports
- List of URLs (http and https)
- List of vulnerabilities and for every vulnerability:
  - List of affected IP addresses
  - List of CVEs

In the end it will also consolidate everything and produce results from all the Nessus reports.

```
# Usage:
cd /directory/with/nessus/results
yanp.sh
```

More information here: https://www.infosecmatter.com/nessus-csv-parser-and-extractor/

---

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

---

**adlogin.ps1**

A simple Active Directory login attack tool. It takes list of usernames and a password and tries to login with it against specified AD domain using LDAP (directoryservices).

It retains results in a file in the current working directory, so it can be interrupted and resumed (it will not try to login again if the given user has already been compromised or tried with the given password).

```
Import-Module .\adlogin.ps1

# Usage:
adlogin <userlist.txt> <domain> <password>

# Example:
adlogin users.txt domain.com P@ssw0rd

# Check results (find valid credentials):
gc adlogin.*.txt | sls True
```
