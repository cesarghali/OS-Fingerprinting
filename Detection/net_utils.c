#include "net_utils.h"

uint16_t calc_cksum(uint8_t* hdr, int len)
{
    long sum = 0;

    while(len > 1)
    {
        sum += *((unsigned short*)hdr);
        hdr = hdr + 2;
        if(sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }

    if(len)
    {
        sum += (unsigned short) *(unsigned char *)hdr;
    }
          
    while(sum>>16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}
