CC = g++

#analysis: analysis.o parse.o pcap.o services.o
#	$(CC) -o analysis analysis.o parse.o pcap.o services.o
analysis: analysis.cc parse.c pcap.c services.c
	$(CC) -o analysis analysis.cc parse.c pcap.c services.c

pcap.o: pcap.c pcap.h
	$(CC) -c -o pcap.o pcap.c

statistic.o: statistic.c pcap.h
	$(CC) -c -o statistic.o statistic.c

parse.o: parse.c pcap.h services.h
	$(CC) -c -o parse.o parse.c services.o

analysis.o: analysis.cc parse.h pcap.h services.h
	$(CC) -c -o analysis.o analysis.cc

services.o: services.c services.h
	$(CC) -c -o services.o services.c

clean:
	-rm analysis
	-rm *.o
