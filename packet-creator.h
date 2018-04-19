#ifndef PDS_PACKET_CREATOR_H
#define PDS_PACKET_CREATOR_H

#include <iostream>
#include <netinet/ether.h> // ether header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <pcap.h>
#include <cstdlib>

#define PACKET_DISCOVER 1
#define PACKET_OFFER 2
#define PACKET_REQUEST 3
#define PACKET_ACK 4
#define PACKET_BUFFER_SIZE 1024

#define OPTION_END 0xff
#define OPTION_DHCP_TYPE 0x35
#define OPTION_DHCP_DISCOVER 0x01
#define OPTION_DHCP_OFFER 0x02
#define OPTION_DHCP_REQUEST 0x03
#define OPTION_DHCP_REQUEST_IP 0x32

#define ETHER_HEADER_SHIFT sizeof(struct ether_header)
#define IP_HEADER_SHIFT sizeof(struct iphdr) + sizeof(struct ether_header)
#define UDP_HEADER_SHIFT sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(udphdr)

#pragma pack(push, 1)
struct dhcp_header {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint8_t yiaddr[4];
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t padding[192];
    uint32_t cookie;
    uint8_t options;
};
#pragma pack(pop)

struct pds_packet{
    uint8_t *buffer;
    int size;
};


struct packet_info{
    uint8_t type;
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint8_t req_ip_address[6];
    uint8_t op;
};
using namespace std;

class PacketCreator{
private:
    pcap_t *handle;
    uint8_t* insert_option(uint8_t* options, int *size, uint8_t type, uint8_t length, uint8_t *data);
    uint8_t * insert_option_data(uint8_t* options, int *size, uint8_t value);
    uint8_t * create_option_array(uint8_t type);
    unsigned short in_cksum(unsigned short *addr, int len);
    uint8_t *generate_mac_address();

public:
    void static parse(u_char *args, const struct pcap_pkthdr *header,
               const u_char *packet);
    pds_packet *create_packet(packet_info *info);
    packet_info *create_packet_info(uint8_t type);
    PacketCreator(pcap_t *pcap_handle);
    void packet_parser();
    void send_packet(packet_info *info);

};
#endif //PDS_PACKET_CREATOR_H
