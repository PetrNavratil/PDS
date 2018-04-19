CC=g++
CPPFLAGS=-std=c++11 -Wall -Wextra

all:dhcp-starvation
dhcp-starvation: dhcp-starvation.cpp
	$(CC) $(CPPFLAGS) dhcp-starvation.cpp packet-creator.cpp -o dhcp-starvation -lpcap -pthread

clean:
	rm -f dhcp-starvation

