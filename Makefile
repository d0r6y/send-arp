all: send-arp

send-arp: main.o
	g++ -g -o send-arp main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f send-arp
	rm -f *.o
	 
