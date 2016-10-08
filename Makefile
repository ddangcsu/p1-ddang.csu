all:	clean replicator_worm extorter_worm

replicator_worm:
	g++ replicator_worm.cpp -lssh -o creplicator

extorter_worm:
	g++ extorter_worm.cpp -lssh -o cextorter

clean:
	rm -rf creplicator cextorter /tmp/.ilovecpsc456_bonus.txt
