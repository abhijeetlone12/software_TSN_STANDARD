#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <malloc.h>

#include "headers.h"

#define UDPPORT 6000

int sock_desc;
struct sockaddr_in receiver_addr;
socklen_t sock_struct_len = sizeof(receiver_addr);

struct timeval current_time;

#define YAXIS_PTP 1
#define YAXIS_UDP6666 2
#define YAXIS_UDP7777 3
#define YAXIS_VLAN 4
#define YAXIS_VLAN_PCP2	5
#define YAXIS_VLAN_PCP3	6
#define YAXIS_AVTP 5
#define YAXIS_OTHERS -1


void print_usage()
{
	printf("Usage:\n"
			"  sniff <1> <2> <3>\n"
			"\t1. interface to sniff on\n"
			"\t2. ip address to send data to\n"
			"\t3. interface through which the data is to be sent\n");
	return;
}

void char_print(u_char *string, int8_t num)
{
	for(int i=0; i<num; i++)
	{
		printf("%02x",string[i]);
		if(i!=(num-1))
			printf(":");
	}
    return;
}

// void print_eth(struct my_ethernet *myeth)
// {
// 	char_print(&myeth->ether_shost[0], 6);
// 	printf(" > ");
// 	char_print(&myeth->ether_dhost[0], 6);
// 	printf(" ");
// 	//printf("ethertype:0x%04x ", myeth->ether_type);
// 	return;
// }

// void print_udp(struct my_ip *myip, struct my_udp *myudp)
// {
// 	printf("%s.%u > %s.%u ",
// 				myip->ip_src,
// 				myudp->udph_srcport,
// 				myip->ip_dst,
// 				myudp->udph_destport);
// 	return;
// }

// void get_eth_param(const struct sniff_ethernet *ethernet, struct my_ethernet *myeth)
// {
// 	memset(myeth->ether_shost,'\0',sizeof(myeth->ether_shost));
// 	memset(myeth->ether_dhost,'\0',sizeof(myeth->ether_dhost));

// 	strncpy(myeth->ether_shost,&ethernet->ether_shost[0],6);
// 	strncpy(myeth->ether_dhost,&ethernet->ether_dhost[0],6);
// 	//myeth->ether_type = ntohs(ethernet->ether_type);
// 	return;
// }

// void get_ip_param(const struct sniff_ip *ip, struct my_ip *myip)
// {
// 	memset(&myip->ip_src[0],'\0',sizeof(myip->ip_src));
// 	memset(&myip->ip_dst[0],'\0',sizeof(myip->ip_dst));

// 	myip->ip_proto = ip->ip_proto;
// 	strcpy(&myip->ip_src[0],inet_ntoa(ip->ip_src));
// 	strcpy(&myip->ip_dst[0],inet_ntoa(ip->ip_dst));
// }

// void get_udp_param(const struct sniff_udp *udp, struct my_udp *myudp)
// {
// 	myudp->udph_srcport = ntohs(udp->udph_srcport);
// 	myudp->udph_destport = ntohs(udp->udph_destport);
// 	return;
// }

/* callback function */
void recv_packet(u_char *args,						// user arguments any
				const struct pcap_pkthdr *header,	// packet meta header
				const u_char *packet)				// actual pointer to packet
{
	// HEADERS
	const struct sniff_ethernet *ethernet;	// Ethernet header
	const struct sniff_ethvlan *ethvlan;	// Ethernet with vlan tagged
	const struct sniff_ip *ip; 				// IP header
	const struct sniff_udp *udp; 			// UDP header
	// PAYLOAD
	// const char *payload; 					// Packet payload
	u_int size_ip;
	// my structs
	// struct my_ethernet *myeth;
	struct my_ethvlan *myethvlan;
	// struct my_ip *myip;
	// struct my_udp *myudp;
	struct pcap_pkthdr *mypcapheader;

	u_char ether_smac[6];
	u_char ether_dmac[6];
	u_short ether_type;
	char ip_src[16];
	char ip_dst[16];
	char ip_proto;
	uint16_t udp_srcport;
	uint16_t udp_dstport;
	uint16_t yaxis_val;

	if(header == NULL || packet == NULL)
	{
		printf("Input pointers are NULL.\n");
		return;
	}

	if(timercmp(&(header->ts), &current_time, >))
		timersub(&(header->ts), &current_time, &(mypcapheader->ts));
	else
	{
		printf("Err: packet capture time in past.\n");
		return;
	}
	// if((mypcapheader->ts.tv_sec < 0) || (mypcapheader->ts.tv_usec < 0))
	// {
	// 	printf("Error: neg time.\n");//: htime %ld.%ld, now %ld.%ld, calc_time %ld.%ld\n", 
	// 				// header->ts.tv_sec, 
	// 				// header->ts.tv_usec,
	// 				// current_time.tv_sec,
	// 				// current_time.tv_usec,
	// 				// mypcapheader->ts.tv_sec,
	// 				// mypcapheader->ts.tv_usec);
	// 	return;
	// }

	/* Timestamp */
	printf("[%ld.%06ld] ", 
				mypcapheader->ts.tv_sec, 
				mypcapheader->ts.tv_usec);

	/* Ethernet frame header */
	ethernet = (struct sniff_ethernet*)(packet);
	// Copy Ethernet parameters
	// get_eth_param(ethernet, myeth);
	memset(ether_smac,'\0',sizeof(ether_smac));
	memset(ether_dmac,'\0',sizeof(ether_dmac));

	strncpy(ether_smac,&ethernet->ether_shost[0],6);
	strncpy(ether_dmac,&ethernet->ether_dhost[0],6);
	ether_type = ntohs(ethernet->ether_type);
	// Print Ethernet parameters
	// print_eth(myeth);
	char_print(&ether_smac[0], 6);
	printf(" > ");
	char_print(&ether_dmac[0], 6);
	printf(" ");
	printf("ethertype:0x%04x ", ether_type);


	yaxis_val = YAXIS_OTHERS;
	/* Type of packet */
	switch (ether_type)
	{
		case 0x0800: // IP
				printf("IP ");
				/* IP header */
				ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
				if ((size_ip = IP_HL(ip)*4) < 20) 
					{printf("Err: Invalid IP header length: %u bytes\n", size_ip);return;}
				// Copy IP parameters
				//get_ip_param(ip, myip);
				memset(&ip_src[0],'\0',sizeof(ip_src));
				memset(&ip_dst[0],'\0',sizeof(ip_dst));

				ip_proto = ip->ip_proto;
				strcpy(&ip_src[0],inet_ntoa(ip->ip_src));
				strcpy(&ip_dst[0],inet_ntoa(ip->ip_dst));
				
				switch (ip_proto)
				{
					case 0x01:
							printf("ICMP ");
							yaxis_val = YAXIS_OTHERS;
						break;
					case 0x11:
							printf("UDP ");
							udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
							//get_udp_param(udp, myudp);
							udp_srcport = ntohs(udp->udph_srcport);
							udp_dstport = ntohs(udp->udph_destport);
							//print_udp(myip, myudp);
							printf("%s.%u > %s.%u ",
										ip_src,
										udp_srcport,
										ip_dst,
										udp_dstport);
							if(udp_srcport==320 || udp_srcport==319)
								yaxis_val = YAXIS_PTP;
							else if(udp_srcport==6666)
								yaxis_val = YAXIS_UDP6666;
							else if(udp_srcport==7777)
								yaxis_val = YAXIS_UDP7777;
							else
								yaxis_val = YAXIS_OTHERS;
						break;
					default:
							yaxis_val = YAXIS_OTHERS;
							printf("Other ");
						break;
				}

			break;
		case 0x8100: // Audio Video Transport protocol
				printf("802.1Q VLAN ");
				//yaxis_val = YAXIS_VLAN;
				//TODO assign ethvlan struct
				//extract ethertype value
				//check if AVTP
				myethvlan = (struct my_ethvlan*)(packet);
				/*check for vlan id*/
				if((myethvlan->ether_8021q_header[3] & 0xFF) == 0x05)
				{
					printf("id %x ", myethvlan->ether_8021q_header[3]);
					printf("pcp %x ", (myethvlan->ether_8021q_header[2]>>5));
					if((myethvlan->ether_8021q_header[2]>>5) == 2)
					{
						//printf("matched ");
						yaxis_val = YAXIS_VLAN_PCP2;
					}
					else if((myethvlan->ether_8021q_header[2]>>5) == 3)
					{
						//printf("matched ");
						yaxis_val = YAXIS_VLAN_PCP3;
					}
				}
			break;
		case 0x22F0: // Audio Video Transport protocol
				printf("AVTP ");
				yaxis_val = YAXIS_AVTP;
			break;
		case 0x22EA: // Stream Reservation protocol
				printf("SRP ");
				yaxis_val = YAXIS_OTHERS;
			break;
		default: // Other
				printf("Other ");
				yaxis_val = YAXIS_OTHERS;
			break;
	}
	printf("\n");

	// form the string
	char udp_string[512];

	if(yaxis_val==YAXIS_PTP) // ptp packets
		sprintf(udp_string, "%ld.%06ld %u 0 0 0 0 0 0",
							mypcapheader->ts.tv_sec,
							mypcapheader->ts.tv_usec,
							yaxis_val);
	else if(yaxis_val==YAXIS_UDP6666) // udp port 6666
		sprintf(udp_string, "%ld.%06ld 0 %u 0 0 0 0 0",
							mypcapheader->ts.tv_sec,
							mypcapheader->ts.tv_usec,
							yaxis_val);
	else if(yaxis_val==YAXIS_UDP7777) // udp port 7777
		sprintf(udp_string, "%ld.%06ld 0 0 %u 0 0 0 0",
							mypcapheader->ts.tv_sec,
							mypcapheader->ts.tv_usec,
							yaxis_val);
	else if(yaxis_val==YAXIS_VLAN) // val tagged
		sprintf(udp_string, "%ld.%06ld 0 0 0 %u 0 0 0",
							mypcapheader->ts.tv_sec,
							mypcapheader->ts.tv_usec,
							yaxis_val);
	else if(yaxis_val==YAXIS_VLAN_PCP2) // audio 
		sprintf(udp_string, "%ld.%06ld 0 0 0 0 %u 0 0",
							mypcapheader->ts.tv_sec,
							mypcapheader->ts.tv_usec,
							yaxis_val);
	else if(yaxis_val==YAXIS_VLAN_PCP3) // video
		sprintf(udp_string, "%ld.%06ld 0 0 0 0 0 %u 0",
							mypcapheader->ts.tv_sec,
							mypcapheader->ts.tv_usec,
							yaxis_val);
	else // others (-1)
		sprintf(udp_string, "%ld.%06ld 0 0 0 0 0 0 -1",
							mypcapheader->ts.tv_sec,
							mypcapheader->ts.tv_usec);


	// send the packet
	if (sendto(	sock_desc, 
				udp_string, 
				strlen(udp_string),
				0,
				(struct sockaddr*)&receiver_addr,
				sock_struct_len) < 0)
 	{
		printf("Can't send packet\n");
		return;
	}
	//printf("[OK]\tPackets sent successfully.\n");

	return;
}

int main(int argc, char *argv[])
{
	if(argc != 4)
	{
		print_usage();
		return 0;
	}

	/* Create socket */
    sock_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock_desc < 0)
	{
        printf("Error creating socket\n");
        return -1;
    }
    printf("[OK]\tSocket created successfully.\n");

	const char *opt;
	opt = argv[3];
	const int len = strnlen(opt, IFNAMSIZ);
	if (len == IFNAMSIZ)
	{
		fprintf(stderr, "Too long iface name");
		return 1;
	}
	/* bind to an interface */
	if(setsockopt(	sock_desc, 
					SOL_SOCKET, 
					SO_BINDTODEVICE, 
					opt, 
					len)==-1)
	{
		printf("Error binding socket to the interface %s.\n",opt);
        return -1;
	}
	printf("[OK]\tSocket bound to the interface %s successfully.\n",opt);


    /* Set port and IP */
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(UDPPORT);
	receiver_addr.sin_addr.s_addr = inet_addr(argv[2]);
	//receiver_addr.sin_addr.s_addr = htons(INADDR_ANY);


	/* setting the device */
	char *dev;						// pointer to the device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	// to store the error produced by pcap functions
	pcap_t *handle;					// pointer for session handler
	bpf_u_int32 net;				// IP address of the device
	bpf_u_int32 mask;				// netmask for the device
	struct in_addr s_net, s_mask;
	struct bpf_program fp;			// to store compiled filter expression
	char filter_exp[] = "";			// to store filter expression
	int ret;						//return value

	/* get the device from user */
	//printf("device %s\n", argv[1]);
	dev = argv[1];

	// /* get the available devices to sniff on*/
	// dev = pcap_lookupdev(errbuf);
	// if(dev==NULL)
	// {
	// 	fprintf(stderr,"Couldn't find any device:\n\t%s\n",errbuf);
	// 	return (2);
	// }
	// printf("Available devices: %s\n",dev);
	
	/* open the device for sniffing */
	handle = pcap_open_live(dev, 	//device
							BUFSIZ,	//max no of bytes to be captured
							1,		//promisc mode
							1000,	//read timeout
							errbuf);//error buffer
	if(handle==NULL)
	{
		fprintf(stderr,
				"Couldn't open device:\n\t%s\n",
				errbuf);
		return (2);
	}
	printf("[OK]\topened device %s for sniffing.\n",dev);

	
	/* check the type of link layer header - DLT_EN10MB */
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr,
				"Device %s does not provide Ethernet headers - not supported:\n\t%s\n",
				dev,
				errbuf);
		return (2);
	}
	printf("[OK]\tdevice %s provides Ethernet headers.\n",dev);


	/* find the netmask of the device */
	if(pcap_lookupnet(	dev,
						(bpf_u_int32*)&s_net,
						(bpf_u_int32*)&s_mask,
						errbuf) == -1) 
	{
		fprintf(stderr, 
				"Couldn't get netmask for device %s:\n\t%s\n", 
				dev,
				errbuf);
		net = 0;
		mask = 0;
	}
	char tmp1[16], tmp2[16];
	memset(tmp1,'\0',sizeof(tmp1));
	memset(tmp2,'\0',sizeof(tmp2));
	strcpy(tmp2,inet_ntoa(s_mask));
	strcpy(tmp1,inet_ntoa(s_net));
	printf("[INFO]\tnetwork:%s netmask:%s\n",tmp1,tmp2);


	/* compile filter */
	if (pcap_compile(	handle,		// session handle 
						&fp, 		// compiled filter expression
						filter_exp, // filter expression
						0, 			// optimize
						(bpf_u_int32)s_net.s_addr) == -1) // ip address of the device
	{
		fprintf(stderr, 
				"Couldn't parse filter %s: %s\n\t%s\n", 
				filter_exp, 
				pcap_geterr(handle),
				errbuf);
		return(2);
	}
	printf("[OK]\tparsed the filter: %s\n", filter_exp);

	 /* set the filter */
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, 
				"Couldn't apply filter %s: %s\n\t%s\n", 
				filter_exp, 
				pcap_geterr(handle),
				errbuf);
		return(2);
	}
	printf("[OK]\tfilter applied.\n");

	/* Get current time */
	gettimeofday(&current_time, NULL);
	printf("[INFO]\tcurrent time: %ld.%ld\n", 
					current_time.tv_sec,
					current_time.tv_usec);

	/* receive packets */
	ret = pcap_loop(handle, 	// session handle
					0, 			// no of packets to sniff
					recv_packet,// callback function
					NULL);		// user arguments


	/* cloas the handle */
	pcap_close(handle);

	return 0;
}




