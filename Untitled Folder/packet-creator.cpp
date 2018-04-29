#include "packet-creator.h"

unsigned short
PacketManager::in_cksum(unsigned short *addr, int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char * )(&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

uint8_t* PacketManager::create_option_array(uint8_t value){
    uint8_t *tmp = new uint8_t[1]{value};
    return tmp;
}

void  PacketManager::parse(u_char *args, const struct pcap_pkthdr *header,
           const u_char *packet) {
    struct ether_header *eh = (struct ether_header *) packet;
    struct iphdr *iph = (struct iphdr *) (packet + ETHER_HEADER_SHIFT);
    struct udphdr *udph = (struct udphdr *) (packet + IP_HEADER_SHIFT);
    struct dhcp_header *dhcph = (struct dhcp_header *) (packet + UDP_HEADER_SHIFT);
    PacketManager *packet_creator=reinterpret_cast<PacketManager *>(args);

    uint8_t *options = &(dhcph->options);
    uint8_t type;
    while(*options != 0xff){
        if(*options == OPTION_DHCP_TYPE){
            options = options + 2; // skip length
            type = *options;
            break;
        }
        options = options + 1;
        options = options + (*options);
    }
    packet_info *p = new packet_info;
    if(type == OPTION_DHCP_OFFER){
        cout << "OFFER " << endl;
        memcpy(&(p->src_mac), &(dhcph->chaddr), 6);
        memcpy(&(p->req_ip_address), &(dhcph->yiaddr), 4);
        memset(&(p->dest_mac), 0xff, 6);
        p->type = PACKET_REQUEST;
        packet_creator->send_packet(p);

    } else {
        cout << "ACK " << endl;

    }

}

packet_info *PacketManager::create_packet_info(uint8_t type){
    packet_info *info = new packet_info;
//    uint8_t fake[] = {0xdc, 0xa1, 0xb9, 0x45, 0x9e, 0x0d};
    uint8_t *fake = generate_mac_address();
    switch(type){
        case PACKET_DISCOVER:
            memset(&(info->dest_mac), 0xff, 6);
            memcpy(&(info->src_mac), fake, 6);
            break;
    }
    info->type = type;
    return info;
}

pds_packet *PacketManager::create_packet(packet_info *info){
    uint8_t *buffer = new uint8_t[PACKET_BUFFER_SIZE];
    struct ether_header *eth_header = (struct ether_header *) buffer;
    struct iphdr *ip_header = (struct iphdr *) (buffer + ETHER_HEADER_SHIFT);
    struct udphdr *udp_header = (struct udphdr *) (buffer + IP_HEADER_SHIFT);
    struct dhcp_header *dhcp_headerr = (struct dhcp_header *) (buffer + UDP_HEADER_SHIFT);
    int dhcp_size = sizeof(dhcp_header) -1;
    uint8_t *dhcpOptions = &(dhcp_headerr->options);
    pds_packet *final_packet = new pds_packet;

    memset(buffer, 0, PACKET_BUFFER_SIZE);
    eth_header->ether_type = htons(ETH_P_IP);
    ip_header-> ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->id = 0;
    ip_header->ttl = 20;
    ip_header->protocol = 17;
    dhcp_headerr->cookie = htonl(0x63825363);

    switch(info->type){
        case PACKET_DISCOVER:
            memcpy(&(eth_header->ether_dhost), &(info->dest_mac), 6);
            memcpy(&(eth_header->ether_shost), &(info->src_mac), 6);
            memcpy(&(dhcp_headerr->chaddr), &(info->src_mac), 6);
            ip_header->saddr = inet_addr("0.0.0.0");
            ip_header->daddr = inet_addr("255.255.255.255");
            udp_header->source = htons(68);
            udp_header->dest = htons(67);
            dhcp_headerr->op = 0x01;
            dhcp_headerr->htype = 0x01;
            dhcp_headerr->hlen = 0x06;
            dhcp_headerr->hops = 0x00;
            dhcp_headerr->xid = 0x00;
            dhcp_headerr->flags = htons(0x8000);
            dhcpOptions = insert_option(dhcpOptions, &dhcp_size, OPTION_DHCP_TYPE, 1, create_option_array(OPTION_DHCP_DISCOVER));
            dhcpOptions = insert_option(dhcpOptions, &dhcp_size, OPTION_END, 0, NULL);
            break;
        case PACKET_REQUEST:
            memcpy(&(eth_header->ether_dhost), &(info->dest_mac), 6);
            memcpy(&(eth_header->ether_shost), &(info->src_mac), 6);
            memcpy(&(dhcp_headerr->chaddr), &(info->src_mac), 6);
            ip_header->saddr = inet_addr("0.0.0.0");
            ip_header->daddr = inet_addr("255.255.255.255");
            udp_header->source = htons(68);
            udp_header->dest = htons(67);
            dhcp_headerr->op = 0x02;
            dhcp_headerr->htype = 0x01;
            dhcp_headerr->hlen = 0x06;
            dhcp_headerr->hops = 0x00;
            dhcp_headerr->xid = 0x00;
            dhcp_headerr->flags = htons(0x8000);
            dhcpOptions = insert_option(dhcpOptions, &dhcp_size, OPTION_DHCP_TYPE, 1, create_option_array(OPTION_DHCP_REQUEST));
            dhcpOptions = insert_option(dhcpOptions, &dhcp_size, OPTION_DHCP_REQUEST_IP, 4, info->req_ip_address);
            dhcpOptions = insert_option(dhcpOptions, &dhcp_size, OPTION_END, 0, NULL);
            break;
    }
    udp_header->len = htons(sizeof(udphdr) + dhcp_size);
    ip_header->tot_len = htons(sizeof(iphdr) + sizeof(udphdr) + dhcp_size);
    ip_header->check = in_cksum((unsigned short *) ip_header, sizeof(struct iphdr));
    final_packet -> size = sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr) + dhcp_size;
    final_packet -> buffer = buffer;
    return final_packet;
}

uint8_t *PacketManager::insert_option(uint8_t* options, int *size, uint8_t type, uint8_t length, uint8_t *data){
    uint8_t *tmp_options = options;
    tmp_options = insert_option_data(tmp_options, size, type);
    if(length > 0){
        tmp_options = insert_option_data(tmp_options, size, length);
        memcpy(tmp_options, data, length);
        tmp_options = tmp_options + length;
        *size = (*size) + length;
    }
    return tmp_options;
}

uint8_t * PacketManager::insert_option_data(uint8_t *options, int *size, uint8_t value) {
    *options = value;
    *size = (*size) + 1;
    return options + 1;
}

PacketManager::PacketManager(pcap_t *pcap_handle) {
    handle = pcap_handle;
}

void PacketManager::packet_parser() {
    pcap_loop(handle, -1, parse, reinterpret_cast<u_char*>(this));
}

void PacketManager::send_packet(packet_info *info) {
    pds_packet *pp = create_packet(info);
    int result = pcap_inject(handle, pp->buffer, pp->size);
}

uint8_t *PacketManager::generate_mac_address(){
    srand (time(NULL));
    uint8_t *mac_address = new uint8_t[6];
    mac_address[0] = 0xdc;
    for(int i = 1; i < 6; i++){
        mac_address[i] =  rand() % 256;
    }
    return mac_address;
}





