#ifndef HEADERS_H
#define HEADERS_H

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
#define SIZE_VLANTAG 4  // VLAN tag length
#define SIZE_UDP 20

/* Ethernet header */
struct sniff_ethernet 
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct my_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_ethvlan
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_char ether_8021q_header[SIZE_VLANTAG]; /* 802.1Q VLAN tag */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct my_ethvlan
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_char ether_8021q_header[SIZE_VLANTAG]; /* 802.1Q VLAN tag */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip 
{
    u_char ip_vhl;		    /* version << 4 | header length >> 2 */
    u_char ip_tos;		    /* type of service */
    u_short ip_len;		    /* total length */
    u_short ip_id;		    /* identification */
    u_short ip_off;		    /* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		    /* time to live */
    u_char ip_proto;		/* protocol */
    u_short ip_csum;		/* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct my_ip
{
    u_char ip_proto;		/* protocol */
    char ip_src[16];
    char ip_dst[16];
};

/* UDP header */
struct sniff_udp
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

struct my_udp
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
};

#endif
