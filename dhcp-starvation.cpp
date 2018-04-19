#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include<sys/socket.h>    //for socket ofcourse
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include<netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <pcap.h>
#include "packet-creator.h"
#include <thread>
#include <chrono>
using namespace std;

pcap_t *pcap_handle;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);


int main(int argc, char* argv[]) {

    string interface = "";
    opterr = 0;
    char c;
    struct ifreq ifmac;

    while((c = getopt(argc, argv, ":i:")) != -1){
        switch(c){
            case 'i':
               interface = optarg;
                break;
            case ':':
                    cerr << "Missing argument for " << argv[optind - 1] << endl;
                return EXIT_FAILURE;
            case '?':
                cerr << "Unexpected parameter " << argv[optind - 1] << endl;
                return EXIT_FAILURE;
        }
    }
    if(interface == ""){
        cout << "Parameter -i interface has to be provided" << endl;
        return EXIT_FAILURE;
    }

    int sockedFd;
    if((sockedFd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1){
        cout << "ERROR" << endl;
    }
    memset(&ifmac, 0, sizeof(ifmac));
    strcpy(ifmac.ifr_name, interface.c_str());
    if(ioctl(sockedFd, SIOCGIFHWADDR, &ifmac) < 0){
        return 1;
    }
////        eh -> ether_shost[i] = ((uint8_t *)&ifmac.ifr_hwaddr.sa_data)[i];



    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 0, errbuf);
    if (pcap_handle == NULL)
    {
        cout << "Couldn't open device " << endl;
        return -1;
    }

    struct bpf_program fp;
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", interface.c_str());
        net = 0;
        mask = 0;
    }

    if (pcap_compile(pcap_handle, &fp, "port 67", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", "port 67", pcap_geterr(pcap_handle));
        return(2);
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", "port 67", pcap_geterr(pcap_handle));
        return(2);
    }

    PacketCreator p(pcap_handle);
    thread tmp(&PacketCreator::packet_parser, &p);
    while(true){
        packet_info *info = p.create_packet_info(PACKET_DISCOVER);
        p.send_packet(info);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }



//    pcap_loop(pcap_handle, 1, p.parse, NULL);

    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);
    tmp.join();
    return 0;
}




