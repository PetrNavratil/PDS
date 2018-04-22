CC=g++
CPPFLAGS=-std=c++11 -Wall -Wextra

all:dhcp-rogue
dhcp-rogue: dhcp-rogue.cpp
	$(CC) $(CPPFLAGS) dhcp-rogue.cpp packet-creator.cpp address_manager.cpp -o dhcp-rogue -lpcap -pthread

clean:
	rm -f dhcp-starvation

