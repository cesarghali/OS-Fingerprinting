#include <stdio.h>

int main()
{
    FILE* file;
    int value;
    int value2;

    file = fopen("/proc/sys/net/ipv4/ip_default_ttl", "w");
    if (file != NULL)
    {
        value = 64;
        printf("-> Changing ip_default_ttl to [%d]\n", value);
        fprintf(file, "%d", value);
        fclose(file);
    }
    else
    {
        printf("-> Error in ip_default_ttl\n");    
    }


    file = fopen("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w");
    if (file != NULL)
    {
        value = 0;
        printf("-> Changing icmp_echo_ignore_all to [%d]\n", value);
        fprintf(file, "%d", value);
        fclose(file);
    }
    else
    {
        printf("-> Error in icmp_echo_ignore_all\n");
    }


    file = fopen("/proc/sys/net/ipv4/ip_local_port_range", "w");
    if (file != NULL)
    {
        value = 32768;
        value2 = 61000;
        printf("-> Changing ip_local_port_range to [%d\t%d]\n", value, value2);
        fprintf(file, "%d\t%d", value, value2);
        fclose(file);
    }
    else
    {
        printf("-> Error in ip_local_port_range\n");
    }


    file = fopen("/proc/sys/net/ipv4/tcp_adv_win_scale", "w");
    if (file != NULL)
    {
        value = 2;
        printf("-> Changing tcp_adv_win_scale to [%d]\n", value);
        fprintf(file, "%d", value);
        fclose(file);
    }
    else
    {
        printf("-> Error in tcp_adv_win_scale\n");
    }


    file = fopen("/proc/sys/net/ipv4/tcp_dsack", "w");
    if (file != NULL)
    {
        value = 1;
        printf("-> Changing tcp_dsack to [%d]\n", value);
        fprintf(file, "%d", value);
        fclose(file);
    }
    else
    {
        printf("-> Error in tcp_dsack\n");
    }


    file = fopen("/proc/sys/net/ipv4/tcp_sack", "w");
    if (file != NULL)
    {
        value = 1;
        printf("-> Changing tcp_sack to [%d]\n", value);
        fprintf(file, "%d", value);
        fclose(file);
    }
    else
    {
        printf("-> Error in tcp_sack\n");
    }


    file = fopen("/proc/sys/net/ipv4/tcp_rfc1337", "w");
    if (file != NULL)
    {
        value = 0;
        printf("-> Changing tcp_rfc1337 to [%d]\n", value);
        fprintf(file, "%d", value);
        fclose(file);
    }
    else
    {
        printf("-> Error in tcp_rfc1337\n");
    }


    return 0;
}
