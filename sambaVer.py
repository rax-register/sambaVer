#!/usr/bin/python3

'''

sambaVer.py version 1.3
https://github.com/rax-register/sambaVer

Description: sambaVer.py is a python 3 based scanner for Unix Samba Server version enumeration. 
smbclient versions > 4.5.8 within Kali Linux no longer display the Unix Samba version for all versions.

See: https://bugs.kali.org/view.php?id=4103 for Kali bug report.

The bug hinders users from obtaining info necessary to solve VulnHub's "Kioptrix Level 1" via exploiting the
vulnerable Samba server. Although there are other ways to exploit Kioptrix Level 1 without attacking the Samba
server, it is still a learning point.

Metasploit's auxiliary smb scanner (auxiliary/scanner/smb/smb_version) still detects the correct Samba version,
but sambaVer.py is for those of us who don't like to rely on Metasploit.

This script uses pysmb's smbConnection to connect to a Samba server and generate the required network traffic.
It then reads the packet data (response) from the Samba server and searches for the known pattern of Samba
versions in the reply.

If you insist on using python 2, use sambaVer.py v1.1 from an earlier commit here: 
https://github.com/rax-register/sambaVer/tree/9dfc23167020672c23047f6eda47dd4e86f3e5f6

Dependencies:
  - pysmb  (run 'sudo pip3 install pysmb') 
  
Additional Notes: 

  - Must be run as root. Add 'sudo' to the beginning if you are not root.
  - Built and tested on Kali Linux 2020.2. Not tested to run on Windows (yet).
  - A manual way to find the Samba version is to run tcpdump or Wireshark and visually inspect the responses
    from the Samba server.
  - Offered under the terms of the MIT License. See LICENSE file for details.

author: register
email:  bytesandorbits@gmail

'''

import argparse, os, re, signal, socket, string, subprocess, sys, time
from smb.SMBConnection import SMBConnection
from smb import smb_structs

############################# global variables #############################


# current version
current_Ver = "1.3"

# initialize variable containing a list of printable characters
print_Char = set(string.printable)

# initialize variable to automatically search for exploits using searchsploit. set by command line argument only
get_Exploit = False

# turn off SMB2 for pysmb connections, this is necessary for the script to work against some versions of Samba
smb_structs.SUPPORT_SMB2 = False


########################### end global variables ###########################


############################## function block ##############################


# function to receive and search through socket data for Samba server versions:
def recv_data(_sock):

    # set timeout, make the socket non-blocking, and note the starting time
    _timeout = 1
    _sock.setblocking(0)
    start_Time = time.time()
    
    # local variables to store data
    all_Data = ''
    part_Data = ''
    
    # loop to receive data and search it for Samba versions
    while 1:
        # if data is received, then break after timeout has been reached
        if all_Data and time.time() - start_Time > _timeout:
            break
        
        # if data is not received, wait twice the timeout
        elif time.time() - start_Time > _timeout * 2:
            break
        
        # receive data, decode it, and then parse it for legible characters
        try:
            part_Data = _sock.recvfrom(4096)
            part_Data = part_Data[0].decode('ISO-8859-1').strip()

            legible_Data = ''
            _i = 0
        
            while _i < len(part_Data):
                legible_Data+=str(list([_x for _x in part_Data[_i][0] if _x in print_Char])).strip('[]\'')
                _i += 1

            # search the legible data for a Samba server version and store the result in search_Samba
            search_Samba = re.search(r'(Samba [\d].[\d].[\d]+[a-d]?)', legible_Data, re.I)

            # if we have a Samba version, exit this function and return the version info
            if search_Samba:
                return search_Samba

            else:
                time.sleep(0.1)

        except Exception as _msg:
            pass


# function to exit cleanly:
def clean_exit(_s):

    _s.close()
    sys.exit(0)


# function to deliver the bad news:
def no_soup_for_you(_come_Back_one_Year):
    print("=============================================")
    print("[-]  Error connecting to the smb server") 
    print("[-]  You may be scanning a Windows device or a system that does not have port 139 open")
    print("[-]  Check to ensure the host is a Unix/Linux machine with port 139 open before trying again")          
    print("=============================================\n")
    clean_exit(_come_Back_one_Year)


# function to deliver the good news:
def great_success(_great, _success):

    print("**********************************************")
    print("[+]  Found Unix Samba Version: ", _success)
    print("**********************************************\n")

    # did the user set the '-s' flag? if so we run searchsploit
    if get_Exploit:
        _success = _success[0:9]
        print("Executing searchsploit", _success, ":")
        os.system("searchsploit " + _success)
 
    clean_exit(_great)


# function to handle arguments on the command line:
def parser_stuff():

    global get_Exploit

    # define various command line options for use
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Samba Server IP Address (Mandatory)")
    parser.add_argument("-s", "--searchsploit", help="Run searchsploit against truncated version information detected", action="store_true")

    # process command line arguments               
    args = parser.parse_args()

    # remind user to include the mandatory argument if they forgot
    if not args.target:
        print("Please Specify Samba Server IP address with -t or --target option")                        
        sys.exit(1)                 

    if args.searchsploit:
        get_Exploit = True
        print("Will run a truncated Samba version against searchsploit")
       
    return args.target


# main function:
def main():
    
    # print version info and take care of parsing arguments
    print("sambaVer.py version: ", current_Ver)
    _server = parser_stuff()

    # once arguments are checked, print message
    print("\nExecuting scan against:", _server)
   
    # initialize variables for SMBConnection
    _c = ''
    user_ID = ''
    _password = ''
    client_Machine_name = ''
    server_Name = ''

    # start of primary while loop:
    while True:

        try:
            # create the socket variable to store received data to parse for Unix Samba versions
            _s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

            # establish SMB connection using blank credentials (anonymous)
            _c = SMBConnection(user_ID, _password, client_Machine_name, server_Name)
            _c.connect(_server, 139)
        
            # call the function to receive and process data
            print_Data = recv_data(_s)
            _s.close()
            _c.close

            # if we have a Samba version, call a function to deliver the good news
            if print_Data:
                samba_Ver = print_Data.group(1)
                great_success(_s, samba_Ver)

        # display an error and exit cleanly if a socket connection cannot be established
        except socket.error as msg:
            print("Unable to create socket:", msg)
            clean_exit(_s)

        # handle smb connection errors
        except Exception:
            no_soup_for_you(_s)

        # handle user initiated Ctrl+c interrupts
        except KeyboardInterrupt:
            print("Interrupt received. Cleaning up, then ending program.")
            clean_exit(_s)

############################ end function block ############################


# Engage!
main()
