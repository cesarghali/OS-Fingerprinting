#include "net_utils.h"
#include <iostream>
#include <sstream>
#include <vector>



#define KNOWN_OS	24

struct os_prop
{
    char name[100];
    float score;
};

struct imp_tests
{
//ip tests
    bool ttl;
    bool df;
  
//tcp tests
    bool tcp_mss;
    bool window_scale;
    bool window_size;
    bool syn_pkt_size;
    bool options_order;
    bool ipid;

//http tests
    bool banner_grabber;
};
