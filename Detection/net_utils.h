#ifndef NET_UTILS
#define NET_UTILS


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <net/if.h>
#include <pthread.h>

#include <pcap.h>
#include <errno.h>
#include <netinet/if_ether.h>


#define	TCPOPT_EOL		0	/* End of options */
#define	TCPOPT_NOP		1	/* Nothing */
#define	TCPOPT_MAXSEG		2	/* MSS */
#define TCPOPT_WSCALE   	3	/* Window scaling */
#define TCPOPT_SACKOK   	4	/* Selective ACK permitted */
#define TCPOPT_TIMESTAMP        8	/* Stamp out timestamping! */

#define MAC_HEADER_LEN 14

#ifndef IP_NO_FRAGMENT
#define IP_NO_FRAGMENT 0x4000
#endif

#ifndef IP_PROTO_ICMP
#define IP_PROTO_ICMP           1  /* ICMP protocol */
#endif

#ifndef IP_PROTO_TCP
#define IP_PROTO_TCP            6  /* TCP protocol */
#endif

#ifndef IP_PROTO_UDP
#define IP_PROTO_UDP            17 /* UDP protocol */
#endif

#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_REQUEST_CODE 0

#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REPLY_CODE 0

#define ICMP_ECHO_REQUEST_DATA_LENGTH 50

#define ETH_HEADER_SIZE 14


struct sr_ethernet_hdr
{
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    uint16_t ether_type;                     /* packet type ID */
} __attribute__ ((packed)) ;

struct ip_hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#else
#error "Byte ordering not specified " 
#endif 
    uint8_t ip_tos;			/* type of service */
    uint16_t ip_len;			/* total length */
    uint16_t ip_id;			/* identification */
    uint16_t ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
} __attribute__ ((packed));

struct icmp_hdr
{
    uint8_t   icmp_type;             /* type of the ICMP   */
    uint8_t   icmp_code;             /* code of the ICMO   */
    uint16_t  icmp_cksum;            /* checksum           */
    uint16_t  icmp_id;               /* identification     */
    uint16_t  icmp_seq_n;            /* sequence number    */
} __attribute__ ((packed));

struct tcp_hdr
{
    uint16_t   tcp_src_prt;
    uint16_t   tcp_dst_prt;
    uint32_t   tcp_seq_num;
    uint32_t   tcp_ack_num;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int tcp_rsrvd_1:4;
    unsigned int tcp_dt_ofst:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int tcp_dt_ofst:4;
    unsigned int tcp_rsrvd_1:4;
#else
#error "Byte ordering not specified " 
#endif 
    uint8_t    tcp_flags;
    uint16_t   tcp_window;
    uint16_t   tcp_cksum;
    uint16_t   tcp_urg_ptr;
} __attribute__ ((packed));


uint16_t calc_cksum(uint8_t*, int);


#endif
