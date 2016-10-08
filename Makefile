all:	clean replicator_worm

replicator_worm:
	g++ replicator_worm.cpp -lssh -o creplicator 

clean:
	rm -rf creplicator /tmp/.ilovecpsc456_bonus.txt
