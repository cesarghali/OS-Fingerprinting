#include "net_utils.h"

#include<sys/time.h>
#include<stdio.h>

#define MAX_CONNECTION_NUM 2000
#define MAX_ATTACKERS_NUM 100

#define MAX_ALLOWED_CONNECTIONS 5
#define MAX_ALLOWED_SYN_RST 5

#define MAX_ALLOWED_HALF_OPENED_LIFE 20
#define MAX_ALLOWED_HALF_OPENED 5


void sniffer(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void* handle_packet(void*);

void Process_IP(uint8_t * packet, int length);
void Process_TCP(uint8_t * packet, int length);
void Process_UDP(uint8_t * packet, int length);
void Process_ICMP(uint8_t * packet, int length);
void* analyze_traffic(void*);
int find_attacker(struct in_addr attacker_ip);
void print_timestamp();


struct handle_packet_params
{
    char packet[1500];
    int length;
};




struct tcp_connection
{
    uint16_t src_port;
    uint16_t dst_port;
    bool syn;
    bool ack;
    bool fin;
    bool rst;

    int number_of_syn;
    int time_stamp;

    bool port_scan_detected;
    bool half_opened_detected;
} __attribute__ ((packed)) ;

struct udp_connection
{
    uint16_t src_port;
    uint16_t dst_port;
} __attribute__ ((packed)) ;

struct attacker
{
    struct in_addr attacker_ip;

    struct tcp_connection tcp_conns[MAX_CONNECTION_NUM];
    int tcp_conns_number;
    int tcp_conns_index;

    struct udp_connection udp_conns[MAX_CONNECTION_NUM];
    int udp_conns_number;
    int udp_conns_index;

    int tcp_syn_and_rst_num;

    bool all_port_scan_detected;
    bool tcp_syn_and_rst_num_detected;
} __attribute__ ((packed)) ;
