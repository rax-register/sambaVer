#!/usr/bin/python

'''

sambaVer.py version 1.0

Description: Python-based scanner for Unix Samba Server version enumeration. smbclient versions > 4.5.8 within
Kali Linux no longer display the Unix Samba version for all versions.

See: https://bugs.kali.org/view.php?id=4103 for Kali bug report.

The bug prevents users from obtaining info necessary to solve VulnHub's "Kioptrix Level 1" via exploiting the
vulnerable Samba server version. Although there are other ways to exploit Kioptrix Level 1 without attacking
the Samba server, it is still a learning point.

Metasploit's auxiliary smb scanner (auxiliary/scanner/smb/smb_version) still detects the correct Samba version,
but sambaVer.py is for those of us who don't like to rely on Metasploit.

This script uses smbclient to connect to a Samba server and generate the required network traffic. It then
reads the packet data (response) from the Samba server and searches for known versions of Unix Samba servers,
reporting the first match it finds.

If running the script on a non-Kali machine, you must have smbclient installed for it to function. 
    $ sudo apt install smbclient

Additional Notes: 

This scan can be loud and cause multiple connections to the target server in rapid succession until a Samba
version is detected. 

A manual way to find the Samba version is to run tcpdump or Wireshark and visually inspect the responses
from the Samba server.

author: register
email:  bytesandorbits@gmail


'''

import argparse, os, re, signal, socket, string, subprocess, sys, time

############################# global variables #############################

# current version
current_Ver = "1.0"

# initialize variable containing a list of printable characters
print_Char = set(string.printable)

# initialize variable to double the number of attempts. set by command line argument only
double_Trouble = False

# initialize variable to modify the timeout setting. set by command line argument only
timer_Multiplier = 1

# initialize variable to automatically search for exploits using searchsploit. set by command line argument only
get_Exploit = False

########################### end global variables ###########################


############################## function block ##############################


# function to receive socket data in chunks and then filter it for readable characters:
def recv_data(_sock, _multi):

    # set timeout based on the multiplier and make the socket non-blocking
    timeout = 1 * _multi
    _sock.setblocking(0)
    
    # local variables to store data
    all_Data = []
    part_Data = ''
    
    # starting time
    start_Time = time.time()

    # loop to receive data in chunks and append it to a single variable
    while 1:
        # if data is received, then break after timeout has been reached
        if all_Data and time.time() - start_Time > timeout:
            break
        
        # if data is not received, wait twice the timeout
        elif time.time() - start_Time > timeout * 2:
            break
        
        # receive new data and add it to the array of data
        try:
            part_Data = _sock.recvfrom(4096)
            if part_Data:
                all_Data.append(part_Data)
                # change the starting time
                start_Time = time.time()
            else:
                time.sleep(0.1)

        except:
            pass
    
    # take the received data and filter out non-printable characters
    legible_Data = ''
    _i = 0
        
    while _i < len(all_Data):
        legible_Data+=filter(lambda x: x in print_Char, all_Data[_i][0])
        _i += 1

    # only send back the data needed to search through
    return legible_Data


# function to exit cleanly:
def clean_exit(_s):
    _s.close()
    sys.exit(0)


# function to deliver the bad news:
def no_soup_for_you(_come_back_one_year):
    print "============================================="
    print "[-]  No Unix Samba server detected" 
    print "[-]  You may be scanning a Windows device or a system that does not have ports 139/445 open"
    print "[-]  If you are sure the target is running a Unix Samba server, try running the script again with option '-2x' or option '-D'"          
    print "=============================================\n"
    clean_exit(_come_back_one_year)


# function to deliver the good news:
def great_success(_great, _success):

    global get_Exploit

    print "**********************************************"
    print "[+]  Found Unix Samba Version: ", _success
    print "**********************************************\n"

    if get_Exploit:
        _success = _success[:-3]
        print "Executing searchsploit", _success, ":"
        os.system("searchsploit " + _success)
 
    clean_exit(_great)


# function to handle arguments on the command line:
def parser_stuff():

    global double_Trouble
    global timer_Multiplier
    global get_Exploit

    # define various command line options for use
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Samba Server IP Address (Mandatory)")
    parser.add_argument("-2x", "--double", help="Doubles the attempts to increase success rate on slower connections", action="store_true")
    parser.add_argument("-D", "--Deliberate", help="Doubles the attempts and increases the timer. This will be a slow scan with the highest chance of success.", action="store_true")
    parser.add_argument("-s", "--searchsploit", help="Run searchsploit against truncated version information detected", action="store_true")

    # process command line arguments               
    args = parser.parse_args()

    # remind user to include the mandatory argument if they forgot
    if not args.target:
        print "Please Specify Samba Server with -t or --target option"                        
        sys.exit(1)                 

    # set global variable
    if args.double:
        double_Trouble = True
        print "Doubling the usual number of attempts. If this doesn't work, try -D"

    if args.Deliberate:
        double_Trouble = True
        timer_Multiplier = 4
        print "Doubling the number of attempts and extending the timer on the socket listener. This may take a moment..."

    if args.searchsploit:
        get_Exploit = True
        print "Will run a truncated Samba version against searchsploit"
       
    return args.target


# main function:
def main():

    global timer_Multiplier

    # print version info and take care of parsing arguments
    print "sambaVer.py version: ", current_Ver
    _server = parser_stuff()

    # once arguments are checked, print message
    print "\nExecuting scan against:", _server

    # initialize variables to track the loops without indications of Unix Samba
    non_Samba = 0
    max_Allowed = 2

    # if user set the '-2x' flag, double the number of attempts    
    if double_Trouble:
        max_Allowed = max_Allowed * 2

    # start of primary while loop:
    while True:

        # smbclient --option='client min protocol=NT1' -NL <server IP>
        p = subprocess.Popen(['smbclient', "--option=client min protocol=NT1", '-NL', _server], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            # create the socket variable and call a function to receive and process data
            s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            print_Data = recv_data(s, timer_Multiplier)
            s.close()

            # use re.search to find a Samba version if present in the received printable packet data
            search_Samba = re.search(r'(Samba [\d].[\d].[\d\w].)', print_Data, re.I)

            # if we have a Samba version, call a function to deliver the good news
            if search_Samba:
                samba_Ver = search_Samba.group(1)
                great_success(s, samba_Ver)

            # increment counter if data does not indicate a Unix Samba server
            if "Unix" not in print_Data and "Samba" not in print_Data:
                non_Samba += 1

            # if the primary while loop has executed multiple times with no result, 
            # call the function to deliver the bad news
            if non_Samba > max_Allowed:
                no_soup_for_you(s)

        # display an error and exit cleanly if a socket connection cannot be established
        except socket.error , msg:
            print("Unable to create socket. Error Code:{0}, Message:{1}".format(str(msg[0]), str(msg[1])))
            sys.exit(1)   

        # handle user initiated Ctrl+c interrupts
        except KeyboardInterrupt:
            print "Interrupt received. Cleaning up, then ending program."
            clean_exit(s)

############################ end function block ############################


# Engage!
main()

