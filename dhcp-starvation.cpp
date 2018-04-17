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
using namespace std;
unsigned short csum(unsigned short *buf, int nwords);

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
    uint8_t type;
    uint8_t length;
    uint8_t message;
    uint8_t end;
};

unsigned short in_cksum(unsigned short *addr, int len);

pcap_t *pcap_handle;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);


int main(int argc, char* argv[]) {

    string interface = "";
    opterr = 0;
    char c;
    struct ifreq ifmac;
    char buffer[1024];
    struct ether_header *eh = (struct ether_header *) buffer;
    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ether_header));
    struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
    struct dhcp_header *dhcph = (struct dhcp_header *) (buffer + sizeof(struct iphdr) + sizeof(struct ether_header) +
            sizeof(udphdr));
    struct sockaddr_ll socket_address;

    uint8_t fake[] = {0xdc, 0xa1, 0xb9, 0x45, 0x9e, 0xcc};

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

    // ether header


    memset(buffer, 0, 1024);
    for(int i = 0; i < 6; i++){
        eh -> ether_shost[i] = ((uint8_t *)&ifmac.ifr_hwaddr.sa_data)[i];
        eh -> ether_dhost[i] = 0xff;
    }
    eh -> ether_type = htons(ETH_P_IP);

    iph -> ihl = 5;
    iph -> version = 4;
    iph -> tos = 0;
    iph -> id = htons(54324);
    iph -> ttl = 20;
    iph -> protocol = 17;
    iph -> saddr = inet_addr("0.0.0.0");
    iph -> daddr = inet_addr("255.255.255.255");

    udph -> source = htons(68);
    udph -> dest = htons(67);
    udph -> check = 0x00;


    dhcph -> op = 0x01;
    dhcph -> htype = 0x01;
    dhcph -> hlen = 0x06;
    dhcph -> hops = 0x00;
    dhcph -> xid = 0x00;
    dhcph -> flags = htons(0x8000);

    dhcph -> type = 0x35;
    dhcph -> length = 0x01;
    dhcph -> message = 0x01;
    dhcph -> end = 0xff;

    for(int i = 0; i < 6; i++)
        dhcph -> chaddr[i] = fake[i];

    dhcph -> cookie = htonl(0x63825363);

    udph -> len = htons(sizeof(struct udphdr) + sizeof(dhcp_header));
    iph -> tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(dhcp_header));
    iph->check = in_cksum((unsigned short *) iph, sizeof(struct iphdr));


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

    int result = pcap_inject(pcap_handle, buffer, sizeof(struct udphdr) + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(dhcp_header));
    if (result <= 0)
//        pcap_perror(pcap_handle, "ERROR:");
        cout << "BAD" << endl;


    pcap_loop(pcap_handle, 1, got_packet, NULL);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    struct ether_header *eh = (struct ether_header *) packet;
    struct iphdr *iph = (struct iphdr *) (packet + sizeof(struct ether_header));
    struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr) + sizeof(struct ether_header));
    struct dhcp_header *dhcph = (struct dhcp_header *) (packet + sizeof(struct iphdr) + sizeof(struct ether_header) +
                                                        sizeof(udphdr));

    cout << ntohs(udph->source) << endl;
    cout << ntohs(udph->len) << endl;
    cout << ntohs(udph->check) << endl;
//    cout << dhcph->hlen << endl;
    cout << udph << endl;
    cout << dhcph << endl;
    printf("omg %d\n", dhcph->op);
    cout << "omg " << dhcph->op << endl;
    printf("omg hlen %d\n", dhcph->hlen);
    cout << "omg hlen " << dhcph->hlen << endl;
    printf("bla %d\n", &dhcph);
    printf("YOUR CLIEND ADDRES %d.%d.%d.%d", (dhcph->yiaddr)[0], (dhcph->yiaddr)[1], (dhcph->yiaddr)[2], (dhcph->yiaddr)[3]);
}


unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short
in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *)(&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}





