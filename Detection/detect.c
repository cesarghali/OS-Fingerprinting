#include "detect.h"
#include "interface_ip.c"

using std::string;

pcap_t* descr;

struct in_addr local_ip;

pthread_t analyze_thread;
pthread_t handle_packet_thread;

struct attacker attackers[MAX_ATTACKERS_NUM];
int attackers_index;


int main(int argc, char* argv[])
{
    /*to take the ip address of current machine*/
    std::string eth0_ip = interface_ip();
    int addr_len = eth0_ip.length();
    char* my_interface_ip = ((char*)(malloc(sizeof(char) * addr_len + 1)));   //allocate a string as long as data + 1 (for '\0')
    eth0_ip.copy(my_interface_ip, addr_len, 0);    // copy the ip address of the current machine to my_interface_ip
    my_interface_ip[addr_len] = '\0';

    inet_aton(my_interface_ip, &local_ip);

    memset(attackers, 0, sizeof(attacker) * MAX_ATTACKERS_NUM);
    attackers_index = 0;


    char* dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

    /*** Selecting device to capture from ***/
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { 
        printf("%s\n", errbuf);
        return 1;
    }

    /*** Opening the selected device ***/
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return 1;
    }

    pthread_create(&analyze_thread, NULL, analyze_traffic, NULL);

    pcap_loop(descr, 0, sniffer, NULL);


    return 0;
}

void sniffer(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct handle_packet_params* params = ((handle_packet_params*)(malloc(sizeof(handle_packet_params))));
    memset(params->packet, 0, 1500);
    memcpy(params->packet, packet, pkthdr->len);
    params->length = pkthdr->len;

    pthread_create(&handle_packet_thread, NULL, handle_packet, params);

    //pcap_breakloop(descr);	use this to stop the 'pcap_loop'
}


void* handle_packet(void* args)
{
    struct handle_packet_params* params = ((handle_packet_params*)(args));

    if(!((params->packet[12] == 8) && (params->packet[13] == 0)))	 // ip packet
    {
        return NULL;
    }

    struct ip_hdr* rx_ip_hdr = ((ip_hdr*)(params->packet + ETH_HEADER_SIZE));

    if(rx_ip_hdr-> ip_dst.s_addr != local_ip.s_addr)
    { 
        return NULL;
    }

    Process_IP((uint8_t*)params->packet, params->length);

    switch(rx_ip_hdr->ip_p)
    {
        case IP_PROTO_TCP:
            Process_TCP((uint8_t*)params->packet, params->length);
            break;

        case IP_PROTO_UDP:
            Process_UDP((uint8_t*)params->packet, params->length);
            break;
	
        case IP_PROTO_ICMP:
            Process_ICMP((uint8_t*)params->packet, params->length);
            break;

        default:
            break;
    }
}


void Process_IP(uint8_t * packet, int length)
{

}//end function Process IP


void Process_TCP(uint8_t * packet, int length)
{
    struct ip_hdr* rx_ip_hdr = ((ip_hdr*)(packet + ETH_HEADER_SIZE));
    int length_ip_header = rx_ip_hdr->ip_hl * 4;  // obtain the length of header in bytes to check for options
    char* attacker_ip = inet_ntoa(rx_ip_hdr->ip_src);

    struct tcp_hdr* rx_tcp_hdr = ((tcp_hdr*)(packet + ETH_HEADER_SIZE + length_ip_header)); 
    int length_tcp_header = rx_tcp_hdr->tcp_dt_ofst * 4;  // obtain the length of header in bytes to check for options
    int length_tcp_options = length_tcp_header - 20;


    /* Connectionless Attacks */

    if (rx_tcp_hdr->tcp_flags == 8)
    {
        printf("-> ");
        print_timestamp();
       	printf(": [%s] sent a TCP packet containing only PSH flag (suspecting OSF).\a\n", attacker_ip);
	return;
    }

    if ((rx_tcp_hdr->tcp_flags & 34) == 34)
    {
        printf("-> ");
        print_timestamp();
       	printf(": [%s] sent a TCP packet with SYN and URG flags set (suspecting OSF).\a\n", attacker_ip);
	return;
    }

    if ((rx_tcp_hdr->tcp_flags & 33) == 33)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with FIN and URG flags set (suspecting OSF).\a\n", attacker_ip);
	return;
    }

    if ((rx_tcp_hdr->tcp_flags & 36) == 36)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with RST and URG flags set (suspecting OSF).\a\n", attacker_ip);
	return;
    }

    if (rx_tcp_hdr->tcp_flags == 0)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP null [no flags set] (suspecting OSF).\a\n", attacker_ip);
	return;
    }

    if ((rx_tcp_hdr->tcp_flags & 3) == 3)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with SYN and FIN flags set (suspecting OSF).\a\n", attacker_ip);
	return;
    }

    if ((rx_tcp_hdr->tcp_flags & 5) == 5)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with RST and FIN flags set (suspecting OSF).\a\n", attacker_ip);
	return;
    }

    if ((rx_tcp_hdr->tcp_flags & 6) == 6)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with RST and SYN flags set (suspecting OSF).\a\n", attacker_ip);
   	return;
    }

    if ((rx_tcp_hdr->tcp_flags & 16 == 16) & (rx_ip_hdr->ip_off && 0x4000 == 0x4000) & (htons(rx_tcp_hdr->tcp_window) == 1024))
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP ACK packet with IP DF and a window size of 1024 (suspecting OSF).\a\n", attacker_ip);
	return;    
    }

    if ((rx_tcp_hdr->tcp_flags & 2 == 2) & (rx_ip_hdr->ip_off && 0x4000 == 0x0000) & (htons(rx_tcp_hdr->tcp_window) == 31337) &
        (htons(rx_tcp_hdr->tcp_dst_prt) != 80))		//80 is the only opened port
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP SYN packet without IP DF and a window size of 31337 to a closed port (suspecting OSF).\a\n", attacker_ip);
	return;    
    }

    if ((rx_tcp_hdr->tcp_flags & 2 == 2) & (rx_ip_hdr->ip_off && 0x4000 == 0x4000) & (htons(rx_tcp_hdr->tcp_window) == 32768) &
        (htons(rx_tcp_hdr->tcp_dst_prt) != 80))		//80 is the only opened port
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP SYN packet with IP DF and a window size of 32768 to a closed port (suspecting OSF).\a\n", attacker_ip);
	return;    
    }

    if ((rx_tcp_hdr->tcp_flags & 41) == 41)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with the FIN, PSH, and URG flags set [Xmas tree scan] (suspecting OSF).\a\n", attacker_ip);
	return;    
    }

    if ((rx_tcp_hdr->tcp_flags & 43) == 43)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with the SYN, FIN, PSH, and URG flags set (suspecting OSF).\a\n", attacker_ip);
	return;    
    }

    if ((rx_tcp_hdr->tcp_flags & 194) == 194)
    {
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a TCP packet with the SYN, ECN, and CWR flags set (suspecting OSF).\a\n", attacker_ip);
	return;    
    }

/*####################################################################################################################################*/

    /* Keep State of the Attacker */

    //finding the attacker
    int attacker_index = find_attacker(rx_ip_hdr->ip_src);
    if (attacker_index == -1)	//attacker not found then add it
    {
        attacker_index = attackers_index;
        attackers_index = (attackers_index + 1) % MAX_ATTACKERS_NUM; //increment the index pointing to last attacker  in the array

        memset(&attackers[attacker_index], 0, sizeof(attacker));

        attackers[attacker_index].attacker_ip.s_addr = rx_ip_hdr->ip_src.s_addr;
    }

    //finding the connection
    int tcp_conn_i = -1;	//-1 = no matching connection found from this attacker
    for (int i = 0; i < attackers[attacker_index].tcp_conns_number; i++)
    {
        if ((attackers[attacker_index].tcp_conns[i].src_port == /*htons(*/rx_tcp_hdr->tcp_src_prt/*)*/) &
            (attackers[attacker_index].tcp_conns[i].dst_port == /*htons(*/rx_tcp_hdr->tcp_dst_prt/*)*/))
        {
            tcp_conn_i = i;	//return the index of the connection
            break;
        }
    }

    if (tcp_conn_i == -1)	//the first packet in the connection
    {
        if ((rx_tcp_hdr->tcp_flags & 2) != 2)	//the packet is not SYN
        {   
            printf("-> ");
            print_timestamp();
            printf(": [%s] sending TCP packets to port [%d] (flags = [%x]) with no established connection (suspecting OSF).\a\n",
                attacker_ip, htons(rx_tcp_hdr->tcp_dst_prt), rx_tcp_hdr->tcp_flags);
        } 
        else if ((rx_tcp_hdr->tcp_flags & 2) == 2)    //the packet is a SYN trying to establish a connection
        { 
	    //add a connection definition to the array
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].src_port = /*htons(*/rx_tcp_hdr->tcp_src_prt/*)*/;
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].dst_port = /*htons(*/rx_tcp_hdr->tcp_dst_prt/*)*/;
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].syn = true;

            time_t time_stamp;
            time(&time_stamp);
            attackers[attacker_index].tcp_conns[ attackers[attacker_index].tcp_conns_index].time_stamp = ((int)(time_stamp));

	    //increment the number of connections for this IP and add one to the index
            attackers[attacker_index].tcp_conns_number++;
            attackers[attacker_index].tcp_conns_index = (attackers[attacker_index].tcp_conns_index +1) % MAX_CONNECTION_NUM;  	     
		
	    //increment the number of SYN packets received on this connection
	    attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].number_of_syn++;
        }
    }
    else	//connection already exists
    {
        if ((rx_tcp_hdr->tcp_flags & 2) == 2)	//the packet is SYN
	{     		
	    //increment the number of SYN packets received on this connection
	    attackers[attacker_index].tcp_conns[tcp_conn_i].number_of_syn++;   
	}
        else if ((rx_tcp_hdr->tcp_flags & 16) == 16)	//the packet is ACK
        {
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].ack = true;
        }
        else if ((rx_tcp_hdr->tcp_flags & 4) == 4)	//the packet is RST
        {
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].rst = true;

            if ((attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].syn == true) &
                (attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].ack == false))
            {
                attackers[attacker_index].tcp_syn_and_rst_num++;
            }
        }
        else if ((rx_tcp_hdr->tcp_flags & 1) == 1)	//the packet is RST
        {
            attackers[attacker_index].tcp_conns[attackers[attacker_index].tcp_conns_index].fin = true;
        }
    }


    /* Check the received options */
    int option_index = 0;
    bool end_of_options = false;

    char* options = ((char*)(malloc(sizeof(char) * 20)));
    memset(options, 0, 20);
        
    int mss = 0;
    int window_scale = 0;
    bool sack;
    uint32_t ts_val = 0;
    uint32_t ts_ecr = 0;

    while(end_of_options == false & option_index < length_tcp_options)
    {
        switch(packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index])
        {
            case TCPOPT_EOL:
                end_of_options = true;
                break;

            case TCPOPT_NOP:
                strcat(options, "N");
                option_index++;
                break;

            case TCPOPT_MAXSEG:
                strcat(options, "M");
                option_index += packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 1];
                mss = (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 2] * 256) +
                    packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 3];
                break;

            case TCPOPT_WSCALE:
                strcat(options, "W");
                option_index += packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 1];
                window_scale = packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 2];
                break;

            case TCPOPT_SACKOK:
                strcat(options, "S");
                option_index += packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 1];
                sack = true;
                break;

            case TCPOPT_TIMESTAMP:
                strcat(options, "T");
                option_index += packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 1];
                ts_val = (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 2] * 256 * 256 * 256) +
                    (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 2] * 256 * 256) +
                    (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 4] * 256) +
                    packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 5];
                ts_ecr = (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 6] * 256 * 256 * 256) +
                    (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 7] * 256 * 256) +
                    (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 8] * 256) +
                    packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 9];
                break;
        }
    }

    if (strcmp(options, "WNMTS") == 0)
    {
        if ((window_scale == 10) & (mss == 1460) & (ts_val == 0xffffffff) & (ts_ecr == 0) & (sack == true) & htons(rx_tcp_hdr->tcp_window) == 1)
        {
            printf("-> ");
            print_timestamp();
            printf(": [%s] sending strange TCP options combination [WNMTS] (suspecting OSF).\a\n", attacker_ip, htons(rx_tcp_hdr->tcp_dst_prt));
        }
    }

    if (strcmp(options, "MWST") == 0)
    {
        if ((mss == 1400) & (window_scale == 0) & (sack == true) & (ts_val == 0xffffffff) & (ts_ecr == 0) & htons(rx_tcp_hdr->tcp_window) == 63)
        {
            printf("-> ");
            print_timestamp();
            printf(": [%s] sending strange TCP options combination [MWST] (suspecting OSF).\a\n", attacker_ip, htons(rx_tcp_hdr->tcp_dst_prt));
        }
    }

    if (strcmp(options, "TNNWNM") == 0)
    {
        if ((ts_val == 0xffffffff) & (ts_ecr == 0) & (window_scale == 5) & (mss == 640) & htons(rx_tcp_hdr->tcp_window) == 4)
        {
            printf("-> ");
            print_timestamp();
            printf(": [%s] sending strange TCP options combination [TNNWNM] (suspecting OSF).\a\n", attacker_ip, htons(rx_tcp_hdr->tcp_dst_prt));
        }
    }

    if (strcmp(options, "STW") == 0)
    {
        if ((sack == true) & (ts_val == 0xffffffff) & (ts_ecr == 0) & (window_scale == 10) & htons(rx_tcp_hdr->tcp_window) == 4)
        {
            printf("-> ");
            print_timestamp();
            printf(": [%s] sending strange TCP options combination [STW] (suspecting OSF).\a\n", attacker_ip, htons(rx_tcp_hdr->tcp_dst_prt));
        }
    }

    if (strcmp(options, "MSTW") == 0)
    {
        if ((mss == 536) & (sack == true) & (ts_val == 0xffffffff) & (ts_ecr == 0) & (window_scale == 10) & htons(rx_tcp_hdr->tcp_window) == 16)
        {
            printf("-> ");
            print_timestamp();
            printf(": [%s] sending strange TCP options combination [MSTW] (suspecting OSF).\a\n", attacker_ip, htons(rx_tcp_hdr->tcp_dst_prt));
        }
    }

    if (strcmp(options, "MST") == 0)
    {
        if ((mss == 256) & (sack == true) & (ts_val == 0xffffffff) & (ts_ecr == 0) & htons(rx_tcp_hdr->tcp_window) == 512)
        {
            printf("-> ");
            print_timestamp();
            printf(": [%s] sending strange TCP options combination [options = MST] (suspecting OSF).\a\n", attacker_ip,
                htons(rx_tcp_hdr->tcp_dst_prt));
        }
    }
}//end function Process TCP


void Process_UDP(uint8_t * packet, int length)
{
}


void Process_ICMP(uint8_t * packet, int length)
{
    struct ip_hdr* rx_ip_hdr = ((ip_hdr*)(packet + ETH_HEADER_SIZE));
    int length_ip_header = rx_ip_hdr->ip_hl * 4;  // obtain the length of header in bytes to check for options
    char* attacker_ip = inet_ntoa(rx_ip_hdr->ip_src);

    struct icmp_hdr* rx_icmp_hdr = ((icmp_hdr*)(packet + ETH_HEADER_SIZE + length_ip_header)); 

    if ((rx_icmp_hdr->icmp_type == 8) & (rx_icmp_hdr->icmp_code > 0))
    {   
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a ICMP Echo packet with invalid 'code' value (suspecting OSF).\a\n", attacker_ip);
    }

    if ((rx_icmp_hdr->icmp_type == 1) | (rx_icmp_hdr->icmp_code == 2) | (rx_icmp_hdr->icmp_code == 7) |
        ((rx_icmp_hdr->icmp_code >= 19) & (rx_icmp_hdr->icmp_code <= 29)) | (rx_icmp_hdr->icmp_code >= 42))
    {	
        printf("-> ");
        print_timestamp();
        printf(": [%s] sent a ICMP packet with reserved 'type' value (suspecting OSF).\a\n", attacker_ip);
    }
}


void* analyze_traffic(void*)
{	
    while(1)
    {
        for (int i = 0; i < MAX_ATTACKERS_NUM; i++)
        {
            if (attackers[i].attacker_ip.s_addr == 0)
            {
                continue;
            }


            int open_conx = 0;  // all open connections to the server
            time_t time_stamp;
            int current_time_stamp;

            for (int j = 0; j < /*attackers[i].tcp_conns_number*/MAX_CONNECTION_NUM; j++)
            {
                open_conx += attackers[i].tcp_conns[j].number_of_syn;



                if(((attackers[i].tcp_conns[j].number_of_syn) >= MAX_ALLOWED_CONNECTIONS) && (attackers[i].tcp_conns[j].port_scan_detected == false))
                {
                    // to show the message only once if detected the port scan
                    attackers[i].tcp_conns[j].port_scan_detected = true;

                    char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                    printf("-> ");
                    print_timestamp();
                    printf(": [%s] connected multiple times with the same {src_prt = %d} and {dst_prt = %d} (suspecting OSF).\a\n", attacker_ip,
                        htons(attackers[i].tcp_conns[j].src_port), htons(attackers[i].tcp_conns[j].dst_port));
                }



                int half_opened_num = 0;  // number of half-opened connections

                if (attackers[i].tcp_conns[j].half_opened_detected == false)
                {
                    time(&time_stamp);
                    current_time_stamp = ((int)(time_stamp));

                    if ((attackers[i].tcp_conns[j].syn == true) & (attackers[i].tcp_conns[j].ack == false) &
                        (attackers[i].tcp_conns[j].rst == false) & (attackers[i].tcp_conns[j].fin == false) &
                        ((current_time_stamp - attackers[i].tcp_conns[j].time_stamp) >= MAX_ALLOWED_HALF_OPENED_LIFE))
                    {
                        half_opened_num++;
                    }

                    for (int k = 0; k < /*attackers[i].tcp_conns_number*/MAX_CONNECTION_NUM; k++)
                    {
                        if (k == j)
                        {
                            continue;
                        }

                        if (attackers[i].tcp_conns[k].half_opened_detected == false)
                        {
                            if (attackers[i].tcp_conns[k].dst_port == attackers[i].tcp_conns[j].dst_port)
                            {
                                time(&time_stamp);
                                current_time_stamp = ((int)(time_stamp));

                                if ((attackers[i].tcp_conns[k].syn == true) & (attackers[i].tcp_conns[k].ack == false) &
                                    (attackers[i].tcp_conns[k].rst == false) & (attackers[i].tcp_conns[k].fin == false) &
                                    ((current_time_stamp - attackers[i].tcp_conns[k].time_stamp) >= MAX_ALLOWED_HALF_OPENED_LIFE))
                                {
                                    half_opened_num++;
                                }
                            }
                        }
                    }

                    if (half_opened_num >= MAX_ALLOWED_HALF_OPENED)
                    {
                        attackers[i].tcp_conns[j].half_opened_detected = true;

                        for (int k = 0; k < /*attackers[i].tcp_conns_number*/MAX_CONNECTION_NUM; k++)
                        {
                            if (attackers[i].tcp_conns[k].dst_port == attackers[i].tcp_conns[j].dst_port)
                            {
                                attackers[i].tcp_conns[k].half_opened_detected = true;
                            }
                        }

                        char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                        printf("-> ");
                        print_timestamp();
                        printf(": [%s] established multiple half-opened connections to port [%d] [each with life > %d secs] (suspecting OSF).\a\n",
                            attacker_ip, htons(attackers[i].tcp_conns[j].dst_port), MAX_ALLOWED_HALF_OPENED_LIFE);
                    }
                }
            }

            if(open_conx > (MAX_ALLOWED_CONNECTIONS * 3) && (attackers[i].all_port_scan_detected == false))
            {
                attackers[i].all_port_scan_detected = true;

                char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                printf("-> ");
                print_timestamp();
                printf(": [%s] attempting a port scan (suspecting OSF).\a\n", attacker_ip);
                //printf(": [%s] IS attempting a Port scan.\a\n", attacker_ip);
            }

            if ((attackers[i].tcp_syn_and_rst_num >= MAX_ALLOWED_SYN_RST) & (attackers[i].tcp_syn_and_rst_num_detected == false))
            {
                attackers[i].tcp_syn_and_rst_num_detected = true;

                char* attacker_ip = inet_ntoa(attackers[i].attacker_ip);
                printf("-> ");
                print_timestamp();
                printf(": [%s] sending multiple SYN then RST TCP packet to multiple ports (suspecting OSF).\a\n", attacker_ip);
            }
        }

        //sleep(1);
    }
}


int find_attacker(struct in_addr attacker_ip)
{
    for (int i = 0; i < MAX_ATTACKERS_NUM; i++)
    {
        if (attackers[i].attacker_ip.s_addr == attacker_ip.s_addr)
        {
            return i;
        }
    }

    return -1;
}


void print_timestamp()
{
    struct timeval tv;
    struct tm* ptm;
    char time_string[40];
    long microseconds;

    gettimeofday(&tv, NULL);
    ptm = localtime(&tv.tv_sec);
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", ptm);
    microseconds = tv.tv_usec;
    
    printf("%s.%06ld", time_string, microseconds);
}
