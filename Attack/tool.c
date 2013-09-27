#include "interface_ip.c"
#include "tool.h"

using std::string;
using std::istringstream;


/* DEFINE THE PARAMETERS NEEDED FOR THE CONNECTION */
#define TCP_SOURCE_PORT 10567 
#define TCP_DEST_PORT 80

#define MAC_HEADER_LEN 14


/* GLOBAL VARIABLES AND FUNCTIONS */
void initialize_os_matrix();
void* initialize_sniffer(void*);
void send_http_request(int port_number);
void sniffer(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void Process_IP(uint8_t * packet, int length);
void Process_TCP(uint8_t * packet, int length);
void Process_ICMP(uint8_t * packet, int length);
void print_decision();


string Banner = "";   // to server version obtained from http reply banner

struct os_prop os_matrix[KNOWN_OS];
struct imp_tests tests;

pthread_t sniffer_thread;

pcap_t* descr;

struct in_addr local_ip;
struct in_addr remote_ip;




int main(int argc, char* argv[])
{
    printf("\n\n");

    struct timeval tv;

    if (argc != 2)
    {
        printf("#############################################\n");
        printf("#    This tool performs OS fingerprinting   #\n");
        printf("#    Enter a valid IP in dotted notation    #\n");
        printf("#                                           #\n");
        printf("#    Example: ofp_tool 192.168.1.45         #\n");
        printf("#############################################\n\n\n");
        return 1;
    }


    initialize_os_matrix();

    /*to take the ip address of current machine*/
    std::string eth0_ip = interface_ip();
    int addr_len = eth0_ip.length();
    char* my_interface_ip = ((char*)(malloc(sizeof(char) * addr_len + 1 )));   //allocate a string as long as data + 1 (for '\0')
    eth0_ip.copy(my_interface_ip,addr_len,0);    // copy the ip address of the current machine to my_interface_ip
    my_interface_ip[addr_len]='\0';


    inet_aton(my_interface_ip, &local_ip);
    inet_aton(argv[1], &remote_ip);

    int port_number = 80;


    printf("Initializing the packet sniffer...\n");
    pthread_create(&sniffer_thread, NULL, initialize_sniffer, NULL);

    for (int i = 0; i < 100000; i++);
    sleep(4);

    printf("OS fingerprinting the network device [%s] through port [%d]...\n", argv[1], port_number);
	
    send_http_request(port_number);

    sleep(4);

    pcap_breakloop(descr);	// use this to stop the pcap_loop

    print_decision();

    //while(1);   // to keep the program running since another thread is alive

    printf("\n\n\n");

}//end main



void initialize_os_matrix()
{
    // 0: "Linux 2.1"
    // 1: "Linux 2.0"
    // 2: "Linux 2.0.3x"
    // 3: "Linux 2.2"
    // 4: "Linux 2.4"
    // 5: "Linux 2.6"

    // 6: "Windows 3.11"
    // 7: "Windows 95"
    // 8: "Windows 95b"
    // 9: "Windows 98"
    //10: "Windows ME no SP"
    //11: "Windows NT 4.0 SP6a"
    //12: "Windows 2000 SP2+"
    //13: "Windows 2000 SP3"
    //14: "Windows 2000 SP4"
    //15: "Windows XP SP1+"
    //16: "Windows 2K3"
    //17: "Windows Vista (beta)"

    //18: "MacOS 7.3-8.6 (OTTCP)"
    //19: "MacOS 8.1-8.6 (OTTCP)"
    //20: "MacOS 8.6"
    //21: "MacOS 9.0-9.2"
    //22: "MacOS 9.1 (OT 2.7.4)"
    //23: "MacOS 10.2.6"

    memset(os_matrix, 0, sizeof(os_prop) * KNOWN_OS);

    strcpy(os_matrix[0].name, "Linux 2.1");
    strcpy(os_matrix[1].name, "Linux 2.0");
    strcpy(os_matrix[2].name, "Linux 2.0.3x");
    strcpy(os_matrix[3].name, "Linux 2.2");
    strcpy(os_matrix[4].name, "Linux 2.4");
    strcpy(os_matrix[5].name, "Linux 2.6");

    strcpy(os_matrix[6].name, "Windows 3.11");
    strcpy(os_matrix[7].name, "Windows 95");
    strcpy(os_matrix[8].name, "Windows 95b");
    strcpy(os_matrix[9].name, "Windows 98");
    strcpy(os_matrix[10].name, "Windows ME no SP");
    strcpy(os_matrix[11].name, "Windows NT 4.0 SP6a");
    strcpy(os_matrix[12].name, "Windows 2000 SP2+");
    strcpy(os_matrix[13].name, "Windows 2000 SP3");
    strcpy(os_matrix[14].name, "Windows 2000 SP4");
    strcpy(os_matrix[15].name, "Windows XP SP1+");
    strcpy(os_matrix[16].name, "Windows 2K3");
    strcpy(os_matrix[17].name, "Windows Vista (beta)");

    strcpy(os_matrix[18].name, "MacOS 7.3-8.6 (OTTCP)");
    strcpy(os_matrix[19].name, "MacOS 8.1-8.6 (OTTCP)");
    strcpy(os_matrix[20].name, "MacOS 8.6");
    strcpy(os_matrix[21].name, "MacOS 9.0-9.2");
    strcpy(os_matrix[22].name, "MacOS 9.1 (OT 2.7.4)");
    strcpy(os_matrix[23].name, "MacOS 10.2.6");

    

    tests.ttl = false;
    tests.df = false;
    tests.ipid = false;

    tests.tcp_mss = false;
    tests.window_scale = false;
    tests.window_size = false;
    tests.syn_pkt_size = false;
    tests.options_order = false;

    tests.banner_grabber = false;
}//end initialize_os_matrix



void* initialize_sniffer(void*)
{
    char* dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;


    /* select device to catpture from*/
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { 
        printf("**** Error selecting a decive to capture from ****\n");
        return NULL;
    }

    /* open selected device for reading */
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if(descr == NULL)
    {
        printf("**** Error opening the selected device for reading ****\n");
        return NULL;
    }
	
    pcap_loop(descr, 0, sniffer, NULL);
}//end initialize_sniffer



void send_http_request(int port_number)
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;


    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("**** Error while creating the socket ****\n\n\n");
        return ;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port_number);
    serv_addr.sin_addr.s_addr = remote_ip.s_addr;


    if (connect(sockfd, ((sockaddr*)(&serv_addr)), sizeof(serv_addr)) < 0)
    {
        printf("**** Error while connecting ****\n\n\n");
        return ;
    }


    char* http_request = ((char*)("GET / HTTP/1.0\n\n"));

    send(sockfd, http_request, strlen(http_request), 0);

    /* remove comments for ONLY ONE to shutdown or close the port */
    //close(sockfd);
    //shutdown(sockfd,SHUT_RDWR);
}//end send_http_request 



void sniffer(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    if(!((packet[12] == 8) && (packet[13] == 0)))	 // ip packet
    {
        return;
    }

    struct ip_hdr* rx_ip_hdr = ((ip_hdr*)(packet + 14));

    if((rx_ip_hdr-> ip_src.s_addr != remote_ip.s_addr) || (rx_ip_hdr-> ip_dst.s_addr != local_ip.s_addr))
    { 
        return;
    }
   
    Process_IP((uint8_t*)packet, pkthdr->len);	

    switch(rx_ip_hdr->ip_p)
    {
        case IP_PROTO_TCP:
            Process_TCP((uint8_t*)packet, pkthdr->len);
            break;
	
        case IP_PROTO_ICMP:
            Process_ICMP((uint8_t*)packet, pkthdr->len);
            break;

        default:
            break;

    }//end switch     	
} //end sniffer



void Process_IP(uint8_t * packet, int length)
{
    struct ip_hdr* rx_ip_hdr = ((ip_hdr*)(packet + 14));

    int length_ip_header = rx_ip_hdr->ip_hl * 4;  // obtain the length of header in bytes to check for options	


    /* TTL Test */
    if (tests.ttl == false)
    {
        if (rx_ip_hdr->ip_ttl > 0 & rx_ip_hdr->ip_ttl <= 32)
        {
            os_matrix[6].score += 0.5;		// Windows 3.11
            os_matrix[9].score += 0.5;		// Windows 98
            os_matrix[16].score += 0.5;		// Windows 2K3
        }
        else if (rx_ip_hdr->ip_ttl > 32 & rx_ip_hdr->ip_ttl <= 64)
        {
            os_matrix[0].score += 0.5;		// Linux 1.2
            os_matrix[1].score += 0.5;		// Linux 2.0
            os_matrix[2].score += 0.5;		// Linux 2.0.3x
            os_matrix[3].score += 0.5;		// Linux 2.2
            os_matrix[4].score += 0.5;		// Linux 2.4
            os_matrix[5].score += 0.5;	 	// Linux 2.6

            os_matrix[7].score += 0.5;		// Windows 95
            // Windows 98 [h?]
            os_matrix[10].score += 0.5;		// Windows ME no SP
            os_matrix[16].score += 0.5;		// Windows 2K3

            os_matrix[23].score += 0.5;		// MacOS 10.2.6
        }
        else if (rx_ip_hdr->ip_ttl > 64 & rx_ip_hdr->ip_ttl <= 128)
        {
            os_matrix[8].score += 0.5;		// Windows 95b
            // Windows 98 [h?]
            os_matrix[11].score += 0.5;		// Windows NT 4.0 SP6a
            os_matrix[12].score += 0.5;		// Windows 2K SP2+
            os_matrix[13].score += 0.5;		// Windows 2K SP3
            os_matrix[14].score += 0.5;		// Windows 2K SP4
            os_matrix[15].score += 0.5;		// Windows XP SP1+
            os_matrix[16].score += 0.5;		// Windows 2K3
            os_matrix[17].score += 0.5;		// Windows Vista (beta)
        }
        else if (rx_ip_hdr->ip_ttl > 128 & rx_ip_hdr->ip_ttl <= 255)
        {
            os_matrix[18].score += 0.5;		// MacOS 7.3-8.6
            os_matrix[19].score += 0.5;		// MacOS 8.1-8.6
            os_matrix[20].score += 0.5;		// MacOS 8.6
            os_matrix[21].score += 0.5;		// MacOS 9.0-9.2
            os_matrix[22].score += 0.5;		// MacOS 9.1
        }

        tests.ttl = true;
    }


    /* DF Test */
    if (tests.df == false)
    {
        if ((htons(rx_ip_hdr->ip_off) & 0x4000) == 0x0000)		//DF = 0
        {
            os_matrix[0].score++;		// Linux 1.2
            os_matrix[1].score++;		// Linux 2.0
            os_matrix[2].score++;		// Linux 2.0.3x

            os_matrix[10].score++;		// Windows ME no SP
            os_matrix[16].score++;		// Windows 2K3
        }
        else if ((htons(rx_ip_hdr->ip_off) & 0x4000) == 0x4000)		//DF = 1
        {
            os_matrix[3].score++;		// Linux 2.2
            os_matrix[4].score++;		// Linux 2.4
            os_matrix[5].score++;		// Linux 2.6

            os_matrix[6].score++;		// Windows 3.11
            os_matrix[7].score++;		// Windows 95
            os_matrix[8].score++;		// Windows 95b
            os_matrix[9].score++;		// Windows 98
            os_matrix[11].score++;		// Windows NT 4.0 SP6a
            os_matrix[12].score++;		// Windows 2K SP2+
            os_matrix[13].score++;		// Windows 2K SP3
            os_matrix[14].score++;		// Windows 2K SP4
            os_matrix[15].score++;		// Windows XP SP1+
            // Windows 2K3 [h?]
            os_matrix[17].score++;		// Windows Vista (beta)

            os_matrix[18].score++;		// MacOS 7.3-8.6
            os_matrix[19].score++;		// MacOS 8.1-8.6
            os_matrix[20].score++;		// MacOS 8.6
            os_matrix[21].score++;		// MacOS 9.0-9.2
            os_matrix[22].score++;		// MacOS 9.1
            os_matrix[23].score++;		// MacOS 10.2.6
        }

        tests.df = true;
    }
}//end Process_IP



void Process_ICMP(uint8_t * packet, int length)
{
    /* No code is added here since we are not
       using ICMP packet for IS fingerprinting */

}//end function Process_ICMP



void Process_TCP(uint8_t * packet, int length)
{
    struct ip_hdr* rx_ip_hdr = ((ip_hdr*)(packet + 14));
    int length_ip_header = rx_ip_hdr->ip_hl * 4;  // obtain the length of header in bytes to check for options	

    struct tcp_hdr* rx_tcp_hdr = ((tcp_hdr*)(packet + 14 + length_ip_header)); 
    int length_tcp_header = rx_tcp_hdr->tcp_dt_ofst * 4;  // obtain the length of header in bytes to check for options	
    int length_tcp_options = length_tcp_header - 20;



    uint16_t tcp_mss = 0;
    int window_scale = -1;

    if ((rx_tcp_hdr->tcp_flags & 2) == 2) 	
    {
        /* Getting TCP MSS and Window Scale from TCP options */
        int option_index = 0;
        bool end_of_options = false;
        while(end_of_options == false & option_index < length_tcp_options)
        {
            switch(packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index])
            {
                case TCPOPT_EOL:
                    end_of_options = true;
                    break;

                case TCPOPT_NOP:
                    option_index++;
                    break;

                case TCPOPT_MAXSEG:
                    tcp_mss = (packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 2] * 256) +
                        packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 3];
                    option_index += 4;
                    break;

                case TCPOPT_WSCALE:
                    window_scale = packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 2];
                    option_index += 3;
                    break;

                case TCPOPT_SACKOK:
                    option_index += 2;
                    break;

                case TCPOPT_TIMESTAMP:
                    option_index += 10;
                    break;
            }
        }


        /* Checking TCP MMS */
        if(tests.tcp_mss == false)
        {
            if (tcp_mss == 1380)
            {
                os_matrix[22].score++;		// MacOS 9.1
            }

            tests.tcp_mss = true;
        }


        /* Window Scale Test */
        if(tests.window_scale == false)
        {
            if (window_scale == -1)		//no window scale appears in tcp options
            {
                os_matrix[0].score++;		// Linux 1.2
                os_matrix[1].score++;		// Linux 2.0
                os_matrix[2].score++;		// Linux 2.0.3x

                os_matrix[6].score++;		// Windows 3.11
                os_matrix[7].score++;		// Windows 95
                os_matrix[8].score++;		// Windows 95b
                os_matrix[9].score++;		// Windows 98
                os_matrix[10].score++;		// Windows ME no SP
                os_matrix[11].score++;		// Windows NT 4.0 SP6a
                os_matrix[12].score++;		// Windows 2K SP2+
                os_matrix[13].score++;		// Windows 2K SP3
                // Windows 2K SP4 [h?]
                os_matrix[15].score++;		// Windows XP SP1+
                os_matrix[16].score++;		// Windows 2K3

                os_matrix[19].score++;		// MacOS 8.1-8.6
                os_matrix[22].score++;		// MacOS 9.1
            }
            else if (window_scale == 0)
            {
                os_matrix[3].score++;		// Linux 2.2
                os_matrix[4].score++;		// Linux 2.4
                os_matrix[5].score++;		// Linux 2.6

                // Windows 98 [h?]
                // Windows 2K SP4 [h?]
                os_matrix[15].score++;		// Windows XP SP1+
                os_matrix[16].score++;		// Windows 2K3

                os_matrix[18].score++;		// MacOS 7.3-8.6
                os_matrix[20].score++;		// MacOS 8.6
                os_matrix[21].score++;		// MacOS 9.0-9.2
                os_matrix[23].score++;		// MacOS 10.2.6
            }
            else if (window_scale == 1)
            {
                os_matrix[4].score++;		// Linux 2.4
                os_matrix[5].score++;		// Linux 2.6
            }
            else if (window_scale == 2)
            {
                os_matrix[4].score++;		// Linux 2.4
                os_matrix[5].score++;		// Linux 2.6

                // Windows 98 [h?]
                os_matrix[16].score++;		// Windows 2K3
            }

                // Windows 98 [h?] wc = 3

            else if ((window_scale == 5) | (window_scale == 6) | (window_scale == 7))
            {
                os_matrix[5].score++;		// Linux 2.6
            }
            else if (window_scale == 8)
            {
                os_matrix[17].score++;		// Windows Vista (beta)
            }

            tests.window_scale = true;
        }


        /* Window Size Test */
        if(tests.window_size == false)
        {
            int temp_window = htons(rx_tcp_hdr->tcp_window);

            if ((temp_window <= (tcp_mss + 50)) & (temp_window >= (tcp_mss - 50)))
            {
                os_matrix[0].score++;		// Linux 1.2
            }

            if ((temp_window <= (32736 + 70)) & (temp_window >= (32736 - 70)))
            {
                os_matrix[1].score++;		// Linux 2.0
            }
            
            if (((temp_window <= (512 + 50)) & (temp_window >= (512 - 50))) |
                ((temp_window <= (16384 + 70)) & (temp_window >= (16384 - 70))))
            {
                // Linux 2.0.3x [h?]
            }


            if (((temp_window <= (tcp_mss * 11) + 70) & (temp_window >= (tcp_mss * 11) - 70 )) |
               ((temp_window <= (tcp_mss * 20) + 70) & (temp_window >= (tcp_mss * 20) - 70 )))
            {
                os_matrix[3].score++;		// Linux 2.2
            }

            if (((temp_window <= (tcp_mss * 2) + 70) & (temp_window >= (tcp_mss * 2) - 70 )) |
               ((temp_window <= (tcp_mss * 3) + 70) & (temp_window >= (tcp_mss * 3) - 70 )) |
               ((temp_window <= (tcp_mss * 4) + 70) & (temp_window >= (tcp_mss * 4) - 70 )))
            {
                os_matrix[4].score++;		// Linux 2.4
                os_matrix[5].score++;		// Linux 2.6
            }

            if ((temp_window <= (8192 + 70)) & (temp_window >= (8192 - 70)))
            {
                os_matrix[6].score++;		// Windows 3.11
            }

            if (((temp_window <= (tcp_mss * 44) + 70) & (temp_window >= (tcp_mss * 44) - 70 )))
            {
                os_matrix[7].score++;		// Windows 95
            }

            if ((temp_window <= (8192 + 70)) & (temp_window >= (8192 - 70)))
            {
                os_matrix[8].score++;		// Windows 95b
            }

            if ((temp_window <= 65535) & (temp_window >= (65535 - 70)) |
                (temp_window <= (8192 + 70)) & (temp_window >= (8192 - 70)) |
                (temp_window <= (32767 + 70)) & (temp_window >= (32767 - 70)) |
                (temp_window <= (37300 + 70)) & (temp_window >= (37300 - 70)) |
                (temp_window <= (46080 + 70)) & (temp_window >= (46080 - 70)) |
                (temp_window <= (60352 + 70)) & (temp_window >= (60352 - 70)) |
                ((temp_window <= (tcp_mss * 44) + 70) & (temp_window >= (tcp_mss * 44) - 70 )) |
                ((temp_window <= (tcp_mss * 4) + 70) & (temp_window >= (tcp_mss * 4) - 70 )) |
                ((temp_window <= (tcp_mss * 6) + 70) & (temp_window >= (tcp_mss * 6) - 70 )) |
                ((temp_window <= (tcp_mss * 12) + 70) & (temp_window >= (tcp_mss * 12) - 70 )) |
                ((temp_window <= (tcp_mss * 16) + 70) & (temp_window >= (tcp_mss * 16) - 70 )) |
                ((temp_window <= (tcp_mss * 26) + 70) & (temp_window >= (tcp_mss * 26) - 70 )))
            {
                os_matrix[9].score++;		// Windows 98
            }

            if ((temp_window <= (44620 + 70)) & (temp_window >= (44620 - 70)))
            {
                os_matrix[10].score++;		// Windows ME no SP
            }

            if ((temp_window <= (64512 + 70)) & (temp_window >= (64512 - 70)))
            {
                os_matrix[11].score++;		// Windows NT 4.0 SP6a
            }

            if ((temp_window <= (64512 + 70)) & (temp_window >= (64512 - 70)))
            {
                os_matrix[11].score++;		// Windows NT 4.0 SP6a
            }

            if ((temp_window <= (8192 + 70)) & (temp_window >= (8192 - 70)) |
                ((temp_window <= (tcp_mss * 6) + 70) & (temp_window >= (tcp_mss * 6) - 70 )))
            {
                os_matrix[12].score++;		// Windows 2K SP2+
            }

            if ((temp_window <= (64512 + 70)) & (temp_window >= (64512 - 70)) |
                ((temp_window <= (tcp_mss * 44) + 70) & (temp_window >= (tcp_mss * 44) - 70 )))
            {
                os_matrix[13].score++;		// Windows 2K SP3
            }

            if ((temp_window <= 65535) & (temp_window >= (65535 - 70)) |
                (temp_window <= (40320 + 70)) & (temp_window >= (40320 - 70)) |
                (temp_window <= (32767 + 70)) & (temp_window >= (32767 - 70)) |
                ((temp_window <= (tcp_mss * 45) + 70) & (temp_window >= (tcp_mss * 45) - 70 )))
            {
                os_matrix[14].score++;		// Windows 2K SP4
            }

            if ((temp_window <= 65535) & (temp_window >= (65535 - 70)) |
                (temp_window <= (8192 + 70)) & (temp_window >= (8192 - 70)) |
                (temp_window <= (64512 + 70)) & (temp_window >= (64512 - 70)) |
                (temp_window <= (32767 + 70)) & (temp_window >= (32767 - 70)) |
                ((temp_window <= (tcp_mss * 45) + 70) & (temp_window >= (tcp_mss * 45) - 70 )) |
                ((temp_window <= (tcp_mss * 44) + 70) & (temp_window >= (tcp_mss * 44) - 70 )) |
                ((temp_window <= (tcp_mss * 12) + 70) & (temp_window >= (tcp_mss * 12) - 70 )))
            {
                os_matrix[15].score++;		// Windows XP SP1+
            }

            if ((temp_window <= 65535) & (temp_window >= (65535 - 70)) |
                (temp_window <= (32768 + 70)) & (temp_window >= (32768 - 70)) |
                (temp_window <= (16384 + 70)) & (temp_window >= (16384 - 70)))
            {
                os_matrix[16].score++;		// Windows 2K3
            }

            if ((temp_window <= (8192 + 70)) & (temp_window >= (8192 - 70)))
            {
                os_matrix[17].score++;		// Windows Vista (beta)
            }


            if ((temp_window <= (16616 + 70)) & (temp_window >= (16616 - 70)))
            {
                os_matrix[18].score++;		// MacOS 7.3-8.6
                os_matrix[19].score++;		// MacOS 8.1-8.6
            }

            if (((temp_window <= (tcp_mss * 2) + 70) & (temp_window >= (tcp_mss * 2) - 70 )))
            {
                os_matrix[20].score++;		// MacOS 8.6
            }

            if ((temp_window <= (32768 + 70)) & (temp_window >= (32768 - 70)))
            {
                os_matrix[21].score++;		// MacOS 9.0-9.2
            }

            if (((temp_window <= (32768 + 70)) & (temp_window >= (32768 - 70))) |
                ((temp_window <= 65535) & (temp_window >= (65535 - 70))))
            {
                os_matrix[22].score++;		// MacOS 9.1
            }

            if ((temp_window <= (33304 + 70)) & (temp_window >= (33304 - 70)))
            {
                os_matrix[23].score++;		// MacOS 10.2.6
            }

            tests.window_size = true;
        }


        /* Total SYN packet size */
        if(tests.syn_pkt_size == false)
        {
            if (htons(rx_ip_hdr->ip_len) == 44)
            {
                os_matrix[0].score++;		// Linux 1.2
                os_matrix[1].score++;		// Linux 2.0
                os_matrix[2].score++;		// Linux 2.0.3x

                os_matrix[6].score++;		// Windows 3.11
                os_matrix[9].score++;		// Windows 98
                os_matrix[11].score++;		// Windows NT 4.0 SP6a
                os_matrix[16].score++;		// Windows 2K3
            }
            else if (htons(rx_ip_hdr->ip_len) == 48)
            {
                os_matrix[9].score++;		// Windows 98
                os_matrix[10].score++;		// Windows ME no SP
                os_matrix[12].score++;		// Windows 2K SP2+
                os_matrix[13].score++;		// Windows 2K SP3
                os_matrix[14].score++;		// Windows 2K SP4
                os_matrix[15].score++;		// Windows XP SP1+
                os_matrix[16].score++;		// Windows 2K3

                os_matrix[18].score++;		// MacOS 7.3-8.6
                os_matrix[19].score++;		// MacOS 8.1-8.6
                os_matrix[20].score++;		// MacOS 8.6
                os_matrix[21].score++;		// MacOS 9.0-9.2
                os_matrix[22].score++;		// MacOS 9.1
            }
            else if (htons(rx_ip_hdr->ip_len) == 52)
            {
                os_matrix[9].score++;		// Windows 98
                os_matrix[16].score++;		// Windows 2K3
                os_matrix[17].score++;		// Windows Vista (beta)
            }

            else if (htons(rx_ip_hdr->ip_len) == 60)
            {
                os_matrix[3].score++;		// Linux 2.2
                os_matrix[4].score++;		// Linux 2.4
                os_matrix[5].score++;		// Linux 2.6

                os_matrix[7].score++;		// Windows 95
                os_matrix[8].score++;		// Windows 95b

                os_matrix[23].score++;		// MacOS 10.2.6
            }

            tests.syn_pkt_size = true;
        }


        /* TCP options order */
        if(tests.options_order == false)
        {
            option_index = 0;
            end_of_options = false;

            char* options = ((char*)(malloc(sizeof(char) * 20)));
            memset(options, 0, 20);

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
                        break;

                    case TCPOPT_WSCALE:
                        strcat(options, "W");
                        option_index += packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 1];
                        break;

                    case TCPOPT_SACKOK:
                        strcat(options, "S");
                        option_index += packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 1];
                        break;

                    case TCPOPT_TIMESTAMP:
                        strcat(options, "T");
                        option_index += packet[MAC_HEADER_LEN + length_ip_header + 20 + option_index + 1];
                        break;
                }
            }

            if (strcmp(options, "M") == 0)
            {
                os_matrix[0].score += 2.5;		// Linux 1.2
                os_matrix[1].score += 2.5;		// Linux 2.0
                os_matrix[2].score += 2.5;		// Linux 2.0.3x

                os_matrix[6].score += 2.5;		// Windows 3.11
                os_matrix[11].score += 2.5;		// Windows NT 4.0 SP6a
                os_matrix[16].score += 2.5;		// Windows 2K3
            }
            else if (strcmp(options, "MSTNW") == 0)
            {
                os_matrix[3].score += 2.5;		// Linux 2.2
                os_matrix[4].score += 2.5;		// Linux 2.4
                os_matrix[5].score += 2.5;	 	// Linux 2.6
            }

            if (strcmp(options, "MNWNNTNNS") == 0)
            {
                os_matrix[7].score += 2.5;		// Windows 95
                os_matrix[8].score += 2.5;		// Windows 95b
                os_matrix[14].score += 2.5;		// Windows 2K SP4
                os_matrix[15].score += 2.5;		// Windows XP SP1+
                os_matrix[16].score += 2.5;		// Windows 2K3
            }

            if ((strcmp(options, "MNNS") == 0) | (strcmp(options, "MNWNNTNNS") == 0) | (strcmp(options, "MNWNNS") == 0))
            {
                os_matrix[9].score += 2.5;		// Windows 98
            }

            if (strcmp(options, "MNNS") == 0)
            {
                os_matrix[10].score += 2.5;		// Windows ME no SP
                os_matrix[12].score += 2.5;		// Windows 2K SP2+
                os_matrix[13].score += 2.5;		// Windows 2K SP3
                os_matrix[14].score += 2.5;		// Windows 2K SP4
                os_matrix[15].score += 2.5;		// Windows XP SP1+
            }

            if ((strcmp(options, "MNWNNS") == 0) | (strcmp(options, "MNNS") == 0))
            {
                os_matrix[16].score += 2.5;		// Windows 2K3
            }

            if (strcmp(options, "MWNNNS") == 0)
            {
                os_matrix[17].score += 2.5;		// Windows Vista (beta)
            }


            if (strcmp(options, "MW") == 0)
            {
                os_matrix[18].score += 2.5;		// MacOS 7.3-8.6
                os_matrix[20].score += 2.5;		// MacOS 8.6
            }

            if (strcmp(options, "MNNN") == 0)
            {
                os_matrix[19].score += 2.5;		// MacOS 8.1-8.6
            }

            if (strcmp(options, "MWN") == 0)
            {
                os_matrix[21].score += 2.5;		// MacOS 9.0-9.2
            }

            if (strcmp(options, "MNNNN") == 0)
            {
                os_matrix[22].score += 2.5;		// MacOS 9.1
            }

            if (strcmp(options, "MNWNNT") == 0)
            {
                os_matrix[23].score += 2.5;		// MacOS 10.2.6
            }

            tests.options_order = true;
        }


        /* IPID Test */
        if (tests.ipid == false)
        {
            if (htons(rx_ip_hdr->ip_id) != 0)		//IPID != 0
            {
                os_matrix[0].score++;		// Linux 1.2
                os_matrix[1].score++;		// Linux 2.0
                os_matrix[2].score++;		// Linux 2.0.3x
                os_matrix[3].score++;		// Linux 2.2

                os_matrix[6].score++;		// Windows 3.11
                os_matrix[7].score++;		// Windows 95
                os_matrix[8].score++;		// Windows 95b
                os_matrix[9].score++;		// Windows 98
                os_matrix[10].score++;		// Windows ME no SP
                os_matrix[11].score++;		// Windows NT 4.0 SP6a
                os_matrix[12].score++;		// Windows 2K SP2+
                os_matrix[13].score++;		// Windows 2K SP3
                os_matrix[14].score++;		// Windows 2K SP4
                os_matrix[15].score++;		// Windows XP SP1+
                os_matrix[16].score++;		// Windows 2K3
                os_matrix[17].score++;		// Windows Vista (beta)

                os_matrix[18].score++;		// MacOS 7.3-8.6
                os_matrix[19].score++;		// MacOS 8.1-8.6
                os_matrix[20].score++;		// MacOS 8.6
                os_matrix[21].score++;		// MacOS 9.0-9.2
                os_matrix[22].score++;		// MacOS 9.1
                os_matrix[23].score++;		// MacOS 10.2.6
            }
            else if (htons(rx_ip_hdr->ip_id) == 0)	//IPID = 0
            {
                os_matrix[4].score++;		// Linux 2.4
                os_matrix[5].score++;		// Linux 2.6
            }

            tests.ipid = true;
        }
    }


    /* Banner Grabbing */
    
    if (length - (MAC_HEADER_LEN + length_ip_header + length_tcp_header) != 0)
    {	
	int headers_length = (MAC_HEADER_LEN + length_ip_header + length_tcp_header);
	int data_length = length - headers_length;

        char* http_text = ((char*)(malloc(sizeof(char) * (data_length + 1))));   //allocate a string as long as data + 1 (for '\0')
        memset(http_text, 0, data_length + 1); //set all to 0 

        strncpy(http_text, ((char*)(packet + headers_length)),data_length);


        if (strncmp(http_text, "HTTP", 4) == 0)
        {
            string str_http_text(http_text);
            string str_server("Server");
            int server_index = str_http_text.find(str_server);

            if(server_index != string::npos)
            {
                int new_len = data_length - server_index;

                string myStr = str_http_text.substr(server_index,new_len);  //take the string from "Server" and on 

                char* myStr1 = ((char*)(malloc(sizeof(char) * (new_len + 1))));
                myStr.copy(myStr1, new_len, 0);
                myStr1[new_len] = '\0';

	        if (strncmp(myStr1, "Server", 6) == 0)
                {
                    int sp_index = myStr.find_first_of("\r");
                    Banner = myStr.substr(0,sp_index);
                }

                free(myStr1);
	    }
        }

        free(http_text);
    }
}//end Process_TCP



void print_decision()
{
    printf("\n-> Operating Systems probability weight:\n");
    printf("   -------------------------------------\n");
    for (int i = 0; i < KNOWN_OS; i++)
    {
            printf("---> %-31s%.1f\n", os_matrix[i].name, os_matrix[i].score);
    }

    printf("\n-> Possible Operating Systems:\n");
    printf("--------------------------------\n");

    float max_score = os_matrix[0].score;
    for (int i = 1; i < KNOWN_OS; i++)
    {
        if (os_matrix[i].score > max_score)
        {
            max_score = os_matrix[i].score;
        }
    }


    for (int i = 0; i < KNOWN_OS; i++)
    {
        if (os_matrix[i].score == max_score)
        {
            printf("---> %s\n", os_matrix[i].name);
        }
    }

    if(Banner != "")
    {
	printf("---> Running Web ");
	std::cout<<Banner;
    }
}//end print_decision
