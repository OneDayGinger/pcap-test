LDLIBS += -lpcap

all: pcap-test

pcap-test: parse_data.o main.o
	gcc -o pcap-test parse_data.o main.o -lpcap

main.o: parse_data.h main.c

parse_data.o: parse_data.h parse_data.c

clean:
	rm -f pcap-test 
	rm -f *.o
