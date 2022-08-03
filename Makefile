LDLIBS += -lpcap

all: pcap-test

pcap-test: parse_data.o main.o
	g++ -o pcap-test parse_data.o main.o -lpcap

main.o: parse_data.h main.cpp

parse_data.o: parse_data.h parse_data.cpp

clean:
	rm -f pcap-test 
	rm -f *.o