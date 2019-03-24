---
layout: default
---

This repo contains a collection of [Metasploit](https://www.metasploit.com/) modules.

# Included modules

* [Total.js < 3.2.4 Directory Traversal (CVE-2019-8903)](./totaljs_traversal.html)
* [CMS Made Simple (CMSMS) Showtime2 < 3.6.3 File Upload RCE (CVE-2019-9692)](./cmsms_showtime2_rce.html)
* Samsung SmartTV scanner

# Papers, articles and resources

* [Total.js Directory Traversal: try this at home!](./totaljs-directory-traversal-try-this-at-home.html)
* [Total.js Directory Traversal: now part of Rapid7/Metasploit](https://blog.rapid7.com/2019/03/15/metasploit-wrap-up-8/)

# How to

Cloning the repo

```
git clone https://github.com/certimetergroup/metasploit-modules.git
```

Copy the content to the local Metasploit directory

```
mkdir -p ~/.msf4 && cp -r metasploit-modules/modules ~/.msf4/
```

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.