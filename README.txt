###############################################################################
#   Name:       David Dang
#   Email:      ddang.csu@csu.fullerton.edu
#   Language:   Python 2.7.1 and C++
#   Assignment:	1 - Implement 3 worms (replicator, extorter, password thief)
###############################################################################

###############################################################################
#  Assignment Objective
###############################################################################
This assignment is to learn how to code a SSH worm that upon execute will self
replicate and perform various type of payload (from non-malicious to malicious)
The main set of worms are to be implmented in Python and the bonus is implemented
in C++

###############################################################################
#  Document Sections
###############################################################################
1.  Assumption
2.  Observation
3.  Bonus
4.  Directory structures
5.  Program run instruction
6.  Assignment Analysis

###############################################################################
#  Assumption
###############################################################################

Following are the assumption or prerequisite for the worm to work:

1.  The following libraries exists on all the VM machines that the worms
    will run on:
        Python libraries:
        - paramiko
        - netifaces
        - urllib
        - tarfile
        - shutil

        C++ libraries:
        libssh

2.  The following binary program are availables:
        - openssl   (/usr/bin/openssl)
        - nmap      (/usr/bin/nmap)  

3.  All worms when run will create a /tmp/nohup.out file to show the run log

4.  All worms when run will write most files to /tmp directory except for the
    extorter worm which will create the encrypted tar file in /home/<user> and
    /home/<user>/Desktop

5.  The marker files are created as a (dot) file so that it is somewhat hidden
    from view of a typical user.

6.  The python version of the worms will also be replicated as a (dot) file

7.  The c++ version of the worms will be replicated as regular file (not dot)


###############################################################################
#  Observation
###############################################################################

Writing worms is really hard work.  The python version was some what simpler 
due to the availability of libraries that perform the major muscle work for all
communication.  If we had to implement these worm using the raw socket library
it would be very tedious.

Another observation that I see is that unless all the VM has the same library
and the necessary files installed, sometimes the worms would die in the middle
of it tracks.  Therefore, to get a a worm that work really well, it must use
only the available system libraries or rather be completely independent of any
libraries (self sustain) to make it effective.

###############################################################################
#  Bonus
###############################################################################

I did implement the bonus (C++ version) of the worms.
The source files had the same name as the python version but when compile
it will have the added "c" to distinguish the python vs c++ version

The implementation of the bonus (C++ version) worms were really hard.  Even with
the help of the libssh library, it was cumbersome and require almost 3 times
the efforts when compare to the original python version.

###############################################################################
# Directory structures
###############################################################################
We assume that all files will be extracted/untar into a certain /<path>.
The directory tree should be as follow:

/<path>/p1-ddang.csu
        |-- README.txt                  - This README file
        |-- replicator_worm.py          - Python replicator worm
        |-- extorter_worm.py            - Python extorter worm
        |-- passwordthief_worm.py       - Python password thief worm
        |-- bonus/                      - bonus program
            |-- Makefile                - Makefile to compile the worms
            |-- worm_support.h          - header file with some define setting
            |-- replicator_worm.cpp     - C++ replicator worm
            |-- extorter_worm.cpp       - C++ extorter worm
            |-- passwordthief_worm.cpp  - C++ password thief worm


The following are possible files created after execute the worms.

/tmp
  |-- .ilovecpsc456.txt             - Marker indicated the VM is the attacker
  |-- .replicator_infected.txt      - Marker for python replicator
  |-- .extorter_infected.txt        - Marker for python extorter
  |-- .passwordthief_infected.txt   - Marker for python password thief
  |-- nohup.out                     - Output of worm executing log on victim
  |-- .replicator_infected_bonus.txt    - Marker for replicator bonus
  |-- .extorter_infected_bonus.txt      - Marker for extorter bonus
  |-- .passwordthief_infected_bonus.txt - Marker for password thief bonus
  |-- .replicator_worm.py           - Replicated dot file on victim
  |-- .extorter_worm.py             - Replicated dot file on victim
  |-- .passwordthief_worm.py        - Prep file on attacker and replicated on victim
  |-- passwd_xxx.xxx.xxx.xxx        - Stolen passwd file from victims
  |-- replicator_wormc              - Replicated C++ replicator on victim
  |-- extorter_wormc                - Replicated C++ extorter on victim
  |-- passwordthief_wormc           - Replicated C++ password thief on victim


The extorter worms beside the file in /tmp will also created files in /home/<user>

/home/<user>
        |-- Desktop/ransomBonus.txt - Extorter message from C++ worm
        |-- Desktop/ransomNote.txt  - Extorter message from Python worm
        |-- Documents.tar.gz.enc    - Encrypted Documents folder python worm
        |-- Documents.tar.gz.bonus.enc  - Encrypted Documents folder C++ worm


###############################################################################
# Program Run instruction
###############################################################################

I choose to my VM1 as my attacker machine and VM2 and VM3 as victims.

1. First login to VM1 with:
    username: ubuntu
    password: 123456

2. Open a terminal and change directory to the worm path.
    cd /<path>/p1-ddang.csu


3. To run replicator python worm:
    python replicator_worm.py

4. To run extorter python worm:
    python extorter_worm.py

5. To run passwordthief python worm:
    python passwordthief_worm.py


Before running the bonus program, please ensure that the victim VMs are clean.

To run the bonus program:

1. First login to VM1 with:
    username: ubuntu
    password: 123456

2. Open a terminal and change directory to the bonus worm path.
    cd /<path>/p1-ddang.csu/bonus

3. Compile the programs
    make all

4. To run the replicator bonus worm:
    ./replicator_wormc

5. To run the extorter bonus worm:
    NOTE: Make sure the VM2 and VM3 (victims) /home/ubuntu/Documents directory
    is available and contains some documents for the extorting to tar/encrypt

    ./extorter_wormc

6. To run the passwordthief bonus worm:
    NOTE: Make sure to first clean up the /tmp/passwd_XXX.XXX.XXX.XXX on the 
    attacker machine (VM1) to see that the passwordthief actually phone home
    the passwd file that it collected from other victims (VM2 and VM3)

    ./passwordthief_wormc


###############################################################################
# Assignment Analysis
###############################################################################        
This assignment helps to provide hand on understanding of how worms work.
It also helps to show the nature and the amount of effort and work need to put
in to get a worm to work accordingly. Additionally it helps us to see the possible
lack luster of the worm and how we could possibly defend ourselves against 
the easier version of the worm.


###############################################################################
# Credit/Source
###############################################################################        
While working on this assignment I used some information/howto from various
sources to help with the code in the assignment.

- samples code provided with the assignment

- Dr. Gofman for help on C++ codes on fork, supress child stdout, installation
of libssh library on the VM, and also how to compile the program

- Stack overflow for finding the home directory of a user and IP address:
http://stackoverflow.com/questions/2910377/get-home-directory-in-linux-c
http://stackoverflow.com/questions/20800319/how-do-i-get-my-ip-address-in-c-on-linux

- libssh library tutorial site:
http://api.libssh.org/master/libssh_tutorial.html


