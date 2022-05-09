#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> //packet cap library
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses (MAC) are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	    #define IP_RF 0x8000		/* reserved fragment flag */
	    #define IP_DF 0x4000		/* don't fragment flag */
	    #define IP_MF 0x2000		/* more fragments flag */
	    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	    #define TH_FIN 0x01
	    #define TH_SYN 0x02
	    #define TH_RST 0x04
	    #define TH_PUSH 0x08
	    #define TH_ACK 0x10
	    #define TH_URG 0x20
	    #define TH_ECE 0x40
	    #define TH_CWR 0x80
	    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
    };


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset){
    int gap;
    const u_char *ch;

    //offset (%05d means 5 digits)
    printf("%05d    ", offset);

	//hexadecimal
	ch = payload;
	for (int i = 0; i < len; i++){
		printf("%02x ", *ch);
		ch++;
		if (i == 7){
			printf("  ");
		}
	}

	//print space to handle lines less than 8 bytes
	if (len < 8) {
		printf("  ");
	}

	//fill hex gap with spaces if not full
	if (len < 16) {
		gap = 16 - len;
		for (int i = 0; i < gap; i++) {
			printf("	");
		}
	}

	printf("	");

	//ascii
	ch = payload;
	for (int i = 0; i < len; i++) {
		if (isprint(*ch)){
			printf("%c", *ch);
		} else {
			printf(".");
		}
		ch++;
	}
	printf("\n");
	return;

}

//print packet payload data
void print_payload(const u_char *payload, int len) {
	int len_rem = len;
	int line_width = 16; //number of bytes per line
	int line_len;
	int offset = 0;
	const u_char *ch = payload;

	if (len <= 0){
		return;
	}

	//data fits on one line
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	//data spans multiple lines
	while (true) {
		line_len = line_width % len_rem;
		len_rem = len_rem - line_width;
		print_hex_ascii_line(ch, line_len, offset);
		//shift pointer to remaining bytes to print
		ch = ch + line_len;
		//add offset
		offset = offset + line_width;
		if (len_rem <= line_width){
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
	return;
}

//callback function that is passed to pcap_loop(..) and called each time a packet is recieved
//dissects the packet
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static int count = 1;

	//declaring pointers to headers
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;
    
	cout << "Packet #" << count << endl;
    count++;

	//define ethernet header
	ethernet = (struct sniff_ethernet*) (packet); //typecasting
	printf("	Ethernet Type: %d\n", ntohs(ethernet->ether_type));

	//define IP header and compute
	ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4; //multiply by 4 to convert from 4-byte words to bytes
	//ip header minimum 20 bytes
	if (size_ip < 20) { 
		cout << "	Invalid IP Header Length" << endl;
		return;
	}

	//print src and dest IP addresses
	//inet_ntoa converts the Internet host address in, given in network byte order, to a string in IPv4 dotted-decimal notation
	//arrow notation is like dot notation (accessing members) but for pointers
	printf("	From: %s\n", inet_ntoa(ip->ip_src));
	printf("	To: %s\n", inet_ntoa(ip->ip_dst));
	
	//determining protocol
	switch (ip->ip_p){
		case IPPROTO_TCP:
			printf("	Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("	Protocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("	Protocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("	Protocol: IP\n");
			break;
		default:
			printf("	Protocol: Unknown\n");
			break;
	}
	//define and compute TCP header
	tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4; // same thing with IP
	//tcp header minimum 20 bytes
	if (size_tcp < 20) {
		printf("	Invalid TCP Header length \n");
	}

	//Print source and destination port
	//ntohs converts the unsigned short integer netshort from network byte order to host byte order.
	printf("	Src port: %d\n", ntohs(tcp->th_sport));
	printf("	Dest port: %d\n", ntohs(tcp->th_dport));

	//define and compute tcp payload
	payload = (char*) (packet + SIZE_ETHERNET + size_ip + size_tcp);
	// ip size - ip header - tcp header
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	//print payload data
	if (size_payload > 0) {
		printf("	Payload (%d bytes):\n", size_payload);
		print_payload( (u_char*) payload, size_payload);
	}
	else {
		cout << "	No Payload Data" << endl;
	}
}

int main(int argc, char *argv[]){
    const u_char *packet; //the packet
    struct pcap_pkthdr header; //header pcap gives


    //setting device to sniff
    char *dev; //device
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        cout << stderr << " Could not find default device: s%\n" << errbuf << endl;
        return 2;
    }

    cout << "Device: " << dev << endl;

    //opening the device
    pcap_t *handle; //session to handle
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cout << stderr << " Couldn't open device %s: %s\n" << dev << errbuf << endl;
        return 2;
    }

    //grab packet
    //packet = pcap_next(handle, &header);
    //print legnth
    //cout << "jacked a packet with a length of " << header.len << endl;
    //close sessions
    //pcap_close(handle);
    //int count = 50;
	//int pcap_loop(pcap_t *p, int cnt, callback function, u_char *user);
    pcap_loop(handle,-1,callback,NULL);
    return 0;
}

