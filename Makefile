CC=g++
CPPFLAGS=-std=c++11 -Wall -Wextra -pedantic

all:dhcp-starvation
dhcp-starvation: dhcp-starvation.cpp
	$(CC) $(CPPFLAGS) dhcp-starvation.cpp -o dhcp-starvation -lpcap

clean:
	rm -f dhcp-starvation

