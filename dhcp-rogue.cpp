#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include "packet-creator.h"
#include "address_manager.h"
#include <pcap.h>
#include <thread>


using namespace std;
uint32_t get_address(char *value);


int main(int argc, char* argv[]) {
    char *network_interface;
    uint32_t start_ip = 0;
    uint32_t end_ip = 0;
    opterr = 0;
    char c;
    char *splitted_pool;
    struct in_addr addr;
    server_info info;


    while((c = getopt(argc, argv, ":i:p:g:n:d:l:")) != -1){
        switch(c){
            case 'i':
                network_interface = optarg;
                break;
            case 'p':
                splitted_pool = strtok(optarg, "-");
                start_ip = AddressManager::get_address(splitted_pool);
                splitted_pool = strtok(NULL, "-");
                end_ip = AddressManager::get_address(splitted_pool);
                if(start_ip >= end_ip){
                    cerr << "End of IP address pool needs to be greater than its start" << endl;
                    return EXIT_FAILURE;
                }
                break;
            case 'g':
                info.gateway = htonl(AddressManager::get_address(optarg));
                if(info.gateway == 0){
                    cerr << "Invalid gateway" << endl;
                    return EXIT_FAILURE;
                }
                break;
            case 'n':
                info.dns_address = htonl(AddressManager::get_address(optarg));
                if(info.dns_address == 0){
                    cerr << "Invalid dns server" << endl;
                    return EXIT_FAILURE;
                }
                break;
            case 'd':
                info.domain = (uint8_t*)optarg;
                info.domain_length = strlen(optarg);
                cout << "LENGHT VSTUP " << info.domain_length << endl;
                break;
            case 'l':
                info.lease_time = strtol(optarg, NULL, 10);
                if(info.lease_time <= 0){
                    cerr << "Lease time has to been greater than 0" << endl;
                    return EXIT_FAILURE;
                }
                break;
            case ':':
                cerr << "Missing argument for " << argv[optind - 1] << endl;
                return EXIT_FAILURE;
            case '?':
                cerr << "Unexpected parameter " << argv[optind - 1] << endl;
                return EXIT_FAILURE;
        }
    }

    struct bpf_program fp;
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    pcap_t *pcap_handle;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(network_interface, BUFSIZ, 1, 0, errbuf);
    if (pcap_handle == NULL)
    {
        cout << "Couldn't open device " << endl;
        return -1;
    }

    if (pcap_lookupnet(network_interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", network_interface);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(pcap_handle, &fp, "port 68", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", "port 68", pcap_geterr(pcap_handle));
        return(2);
    }

    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", "port 68", pcap_geterr(pcap_handle));
        return(2);
    }

    PacketCreator p(pcap_handle);
    p.set_server_info(info);
    AddressManager addressManager(info.lease_time);
    addressManager.generate_address_pool(start_ip, end_ip);
    thread listener(&PacketCreator::server_listener, &p);
    thread cleaner(&AddressManager::cleaner, &addressManager);
    p.server_responder(&addressManager);

}




