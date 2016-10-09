all:	clean replicator_worm extorter_worm passwordthief_worm

replicator_worm:
	g++ replicator_worm.cpp -lssh -o replicator_wormc

extorter_worm:
	g++ extorter_worm.cpp -lssh -o extorter_wormc

passwordthief_worm:
	g++ passwordthief_worm.cpp -lssh -o passwordthief_wormc

clean:
	rm -rf replicator_wormc extorter_wormc passwordthief_wormc /tmp/.ilovecpsc456_bonus.txt
