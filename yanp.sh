#!/usr/bin/env bash
#
# Postprocess Nessus scan results exported as CSV and parse out
# vulnerabilities, unique IPs, URLs, open ports and resolved hostnames
#
# Version: 1.0
# Contact: dev@infosecmatter.com
#######################################################################

# output file names
out_alive_hosts="hosts.txt"
out_hosts_resolved="hosts.resolved.txt"
out_open_ports="open.ports.txt"
out_url_list="urls.txt"
out_vulns_cve_list="vulns.cve.list.txt"
out_vulns_with_ports="vulns.hosts.with.ports.txt"
out_vulns_without_ports="vulns.hosts.without.ports.txt"

# start processing
for report in *.csv; do
  echo "`date`: processing report ${report}"

  tr -d '\n\r' <"${report}" | sed -e 's/""\([0-9]\+\)"/"\n"\1"/g;s/,Plugin Output"/,Plugin Output\n"/g' >"${report}.tmp"

  # # # # # hosts
  if [ -f "${report/.csv/}-${out_alive_hosts}" ]; then
    echo "`date`: parsing out list of unique hosts seen ..already done"
  else
    echo "`date`: parsing out list of unique hosts seen"
    grep '","[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+","' <"${report}.tmp" | \
      cut -d',' -f5 | tr -d '"' | sort -V | uniq >"${report}-${out_alive_hosts}.tmp"
    mv -f -- "${report}-${out_alive_hosts}.tmp" "${report/.csv/}-${out_alive_hosts}"
  fi

  # # # # # resolved hostnames
  if [ -f "${report/.csv/}-${out_hosts_resolved}" ]; then
    echo "`date`: parsing out list of resolved hostnames ..already done"
  else
    echo "`date`: parsing out list of resolved hostnames"
    grep '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+ resolves as ' <"${report}.tmp" | \
      sed -e 's/.*","//g;s/ resolves as//g;s/\.$//g;s/\."$//g;s/\(.*\)/\L\1/' | sort -V | uniq > "${report}-${out_hosts_resolved}.tmp"
    mv -f -- "${report}-${out_hosts_resolved}.tmp" "${report/.csv/}-${out_hosts_resolved}"
  fi

  # # # # # urls
  if [ -f "${report/.csv/}-${out_url_list}" ]; then
  echo "`date`: parsing out list of unique URLs seen ..already done"
  else
    echo "`date`: parsing out list of unique URLs seen"
    sed -e 's/""\([0-9]\+\)"/"\n"\1"/g' <"${report}.tmp" | \
      awk -F '"' '/A web server is running on this port/{print $10,$14,$26}' | \
      sort -V | uniq | while read ip port msg; do
        if [ "${msg}" == "A web server is running on this port." ]; then
          echo "http://${ip}:${port}/"
          awk "/^${ip}/{print \$2}" *-${out_hosts_resolved} | sort | uniq | while read host; do
            echo "http://${host}:${port}/"
          done
        elif [[ "${msg}" =~ "A web server is running on this port through" ]]; then
          echo "https://${ip}:${port}/"
          awk "/^${ip}/{print \$2}" *-${out_hosts_resolved} | sort | uniq | while read host; do
            echo "https://${host}:${port}/"
          done
        else
          echo "https://${ip}:${port}/  (NOT SURE !!! $msg)"
          awk "/^${ip}/{print \$2}" *-${out_hosts_resolved} | sort | uniq | while read host; do
            echo "https://${host}:${port}/  (NOT SURE !!! $msg)"
          done
        fi
    done | sort -V | uniq >"${report}-${out_url_list}.tmp"
    mv -f -- "${report}-${out_url_list}.tmp" "${report/.csv/}-${out_url_list}"
  fi

  # # # # # open ports
  if [ -f "${report/.csv/}-${out_open_ports}" ]; then
    echo "`date`: parsing out open ports ..already done"
  else
    echo "`date`: parsing out open ports"
    sed -e 's/""\([0-9]\+\)"/"\n"\1"/g' <"${report}.tmp" | \
      awk -F '"' '/was found to be open/{print $10,$14,$12}' | tr ' ' ';' >"${report}-${out_open_ports}.tmp"
    mv -f -- "${report}-${out_open_ports}.tmp" "${report/.csv/}-${out_open_ports}"
  fi

  # # # # # vulns CVEs
  if [ -f "${report/.csv/}-${out_vulns_cve_list}" ]; then
    echo "`date`: parsing out vulnerabilities and their CVEs ..already done"
  else
    echo "`date`: parsing out vulnerabilities and their CVEs"
    for sev in Critical High Medium Low None; do
      grep "\"${sev}\"" "${report}.tmp" | cut -d'"' -f16 | sort | uniq | grep -v '^$' | while read vuln; do
        echo -n "${sev};${vuln};"
        grep "\"${vuln}\"" "${report}.tmp" | cut -d '"' -f4 | sort -V | uniq | tr '\n' ',' | sed -e 's/,/, /g;s/, $//'
        echo
      done
    done >"${report}-${out_vulns_cve_list}.tmp"
    mv -f -- "${report}-${out_vulns_cve_list}.tmp" "${report/.csv/}-${out_vulns_cve_list}"
  fi

  # # # # # vulns affected hosts
  if [ -f "${report/.csv/}-${out_vulns_without_ports}" ]; then
    echo "`date`: parsing out vulnerabilities and affected hosts ..already done"
  else
    echo "`date`: parsing out vulnerabilities and affected hosts"
    for sev in Critical High Medium Low None; do
      grep "\"${sev}\"" "${report}.tmp" | cut -d'"' -f16 | sort | uniq | grep -v '^$' | while read vuln; do
        echo -n "${sev};${vuln};"
        grep "\"${vuln}\"" "${report}.tmp" | cut -d '"' -f10,14 | sort -V | uniq | tr '\n' ',' | sed -e 's/"/:/g;s/,/, /g;s/, $//g'
        echo
      done
    done >"${report}-${out_vulns_with_ports}.tmp"
    mv -f -- "${report}-${out_vulns_with_ports}.tmp" "${report/.csv/}-${out_vulns_with_ports}"
    echo "`date`: parsing out vulnerabilities and affected hosts without ports"
    while read line; do
      vuln="${line%;*}"
      ips="${line##*;}"
      echo -n "${vuln};"
      echo "${ips}" | sed -e 's/:[0-9]\+//g;s/,//g;s/ /\n/g' | sort -V | uniq | tr '\n' ',' | sed -e 's/,/, /g;s/, $//'
      echo
    done <"${report/.csv/}-${out_vulns_with_ports}" >"${report}-${out_vulns_without_ports}.tmp"
    mv -f -- "${report}-${out_vulns_without_ports}.tmp" "${report/.csv/}-${out_vulns_without_ports}"
  fi
done

echo "`date`: done, now consolidating everything"

echo "`date`: generating ${out_alive_hosts}"
cat *-${out_alive_hosts} | sort -V | uniq > ${out_alive_hosts}.tmp
mv -f ${out_alive_hosts}.tmp ${out_alive_hosts}

echo "`date`: generating ${out_hosts_resolved}"
cat *-${out_hosts_resolved} | sort -V | uniq > ${out_hosts_resolved}.tmp
mv -f ${out_hosts_resolved}.tmp ${out_hosts_resolved}

echo "`date`: generating ${out_open_ports}"
cat *-${out_open_ports} | sort -V | uniq > ${out_open_ports}.tmp
mv -f ${out_open_ports}.tmp ${out_open_ports}

echo "`date`: generating ${out_url_list}"
cat *-${out_url_list} | sort -t/ -k3 -V | uniq > ${out_url_list}.tmp
mv -f ${out_url_list}.tmp ${out_url_list}

echo "`date`: generating ${out_vulns_cve_list}"
cat *-${out_vulns_cve_list} | cut -d';' -f1,2 | sort | uniq | while read vuln; do
  echo -n "${vuln};"
  cat *-${out_vulns_cve_list} | grep "^${vuln};" | cut -d';' -f3 | tr -d ',' | tr -s ' ' '\n' | sort -V | uniq | tr '\n' ',' | sed -e 's/,/, /g;s/, $//'
  echo
done > ${out_vulns_cve_list}.tmp
for sev in Critical High Medium Low None; do
  grep "^${sev};" ${out_vulns_cve_list}.tmp
done > ${out_vulns_cve_list}
rm -f ${out_vulns_cve_list}.tmp

# # # # # vulns
echo "`date`: generating ${out_vulns_with_ports}"
cat *-${out_vulns_with_ports} | cut -d';' -f1,2 | sort | uniq | while read vuln; do
  echo -n "${vuln};"
  cat *-${out_vulns_with_ports} | grep "^${vuln};" | cut -d';' -f3 | tr -d ',' | tr -s ' ' '\n' | sort -V | uniq | tr '\n' ',' | sed -e 's/,/, /g;s/, $//'
  echo
done > ${out_vulns_with_ports}.tmp
for sev in Critical High Medium Low None; do
  grep "^${sev};" ${out_vulns_with_ports}.tmp
done > ${out_vulns_with_ports}
rm -f ${out_vulns_with_ports}.tmp

echo "`date`: generating ${out_vulns_without_ports}"
cat *-${out_vulns_without_ports} | cut -d';' -f1,2 | sort | uniq | while read vuln; do
  echo -n "${vuln};"
  cat *-${out_vulns_without_ports} | grep "^${vuln};" | cut -d';' -f3 | tr -d ',' | tr -s ' ' '\n' | sort -V | uniq | tr '\n' ',' | sed -e 's/,/, /g;s/, $//'
  echo
done > ${out_vulns_without_ports}.tmp
for sev in Critical High Medium Low None; do
  grep "^${sev};" ${out_vulns_without_ports}.tmp
done > ${out_vulns_without_ports}
rm -f ${out_vulns_without_ports}.tmp

# # # # # cleanup
for report in *.csv; do
  echo "`date`: cleaning ${report}.tmp"
  rm -f -- "${report}.tmp"
done

echo "`date`: done"

