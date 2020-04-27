# sambaVer
Description:

    Python-based scanner for Unix Samba Server version enumeration. smbclient versions > 4.5.8 within
    Kali Linux no longer display the Unix Samba version for all versions.

    See: https://bugs.kali.org/view.php?id=4103 for Kali bug report.

    The bug prevents users from obtaining info necessary to solve VulnHub's "Kioptrix Level 1" via 
    exploiting the vulnerable Samba server version. Although there are other ways to exploit Kioptrix
    Level 1 without attacking the Samba server, it is still a learning point.

    Metasploit's auxiliary smb scanner (auxiliary/scanner/smb/smb_version) still detects the correct
    Samba version, but sambaVer.py is for those of us who don't like to rely on Metasploit.

    This script uses smbclient to connect to a Samba server and generate the required network traffic.
    It then reads the packet data (response) from the Samba server and searches for known versions of
    Unix Samba servers, reporting the first match it finds.

    If running the script on a non-Kali machine, you must have smbclient installed for it to function. 
        $ sudo apt install smbclient

    Additional Notes: 

    This scan can be loud and cause multiple connections to the target server in rapid succession
    until a Samba version is detected. 

    A manual way to find the Samba version is to run tcpdump or Wireshark and visually inspect the
    responses from the Samba server.

    author: register
    email:  bytesandorbits@gmail

Usage:

    root@kali:~#  ./sambaVer.py -h
    sambaVer.py version:  1.0
    usage: sambaVer.py [-h] [-t TARGET] [-2x] [-D] [-s]

    optional arguments:
    -h, --help            show this help message and exit
    -t TARGET, --target TARGET 
                          Samba Server IP Address (Mandatory)
    -2x, --double         Doubles the attempts to increase success rate on slower connections
    -D, --Deliberate      Doubles the attempts and increases the timer. This will be a slow scan
                          with the highest chance of success.
    -s, --searchsploit    Run searchsploit against truncated version information
                          detected


    root@kali:~# ./sambaVer.py -t 192.168.110.132
    sambaVer.py version:  1.0

    Executing scan against: 192.168.110.132
    **********************************************
    [+]  Found Unix Samba Version:  Samba 2.2.1a
    **********************************************


    root@kali:~# ./sambaVer.py -s -t 192.168.110.132
    sambaVer.py version:  1.0
    Will run a truncated Samba version against searchsploit

    Executing scan against: 192.168.110.132
    **********************************************
    [+]  Found Unix Samba Version:  Samba 2.2.1a
    **********************************************
    
    Executing searchsploit Samba 2.2 :
    ------------------------------------------------------------ ----------------------------------------
     Exploit Title                                              |  Path
                                                                | (/usr/share/exploitdb/)
    ------------------------------------------------------------ ----------------------------------------
    Samba 2.0.x/2.2 - Arbitrary File Creation                   | exploits/unix/remote/20968.txt
    Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit | exploits/osx/remote/9924.rb
    Samba 2.2.2 < 2.2.6 - 'nttrans' Remote Buffer Overflow (Met | exploits/linux/remote/16321.rb
    Samba 2.2.8 (BSD x86) - 'trans2open' Remote Overflow (Metas | exploits/bsd_x86/remote/16880.rb
    Samba 2.2.8 (Linux Kernel 2.6 / Debian / Mandrake) - Share  | exploits/linux/local/23674.txt
    Samba 2.2.8 (Linux x86) - 'trans2open' Remote Overflow (Met | exploits/linux_x86/remote/16861.rb
    Samba 2.2.8 (OSX/PPC) - 'trans2open' Remote Overflow (Metas | exploits/osx_ppc/remote/16876.rb
    Samba 2.2.8 (Solaris SPARC) - 'trans2open' Remote Overflow  | exploits/solaris_sparc/remote/16330.rb
    Samba 2.2.8 - Brute Force Method Remote Command Execution   | exploits/linux/remote/55.c
    Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (1)  | exploits/unix/remote/22468.c
    Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (2)  | exploits/unix/remote/22469.c
    Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (3)  | exploits/unix/remote/22470.c
    Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (4)  | exploits/unix/remote/22471.txt
    Samba 2.2.x - 'nttrans' Remote Overflow (Metasploit)        | exploits/linux/remote/9936.rb
    Samba 2.2.x - CIFS/9000 Server A.01.x Packet Assembling Buf | exploits/unix/remote/22356.c
    Samba 2.2.x - Remote Buffer Overflow                        | exploits/linux/remote/7.pl
    Samba < 2.2.8 (Linux/BSD) - Remote Code Execution           | exploits/multiple/remote/10.c
    ------------------------------------------------------------ ----------------------------------------
    Shellcodes: No Result
    
