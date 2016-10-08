all:	replicator_worm

replicator_worm:
	g++ replicator_worm.cpp -lssh -o replicator_worm

clean:
	rm -rf replicator_worm /tmp/.ilovecpsc456_bonus.txt
