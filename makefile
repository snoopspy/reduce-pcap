all : reduce-pcap

reduce-pcap : main.cpp
	g++ -o reduce-pcap -O2 main.cpp -lpcap

clean:
	rm -f *.o reduce-pcap

