#include <string>
#include <fstream> // for ifstream
#include <iostream> // for cout and endl
#include <unistd.h> // for unlink()
#include <stdlib.h>

std::string interface_ip()
{
// attempt to obtain ifconfig information
system( "/sbin/ifconfig eth0 2> /dev/null"
"| /bin/grep -m 1 addr: | /usr/bin/cut -d : -f2"
"| /usr/bin/cut -d ' ' -f1 > /tmp/sysinfo;" );

system( "/sbin/ifconfig eth0 2> /dev/null"
"| /bin/grep -m 1 Bcast: | /usr/bin/cut -d : -f3"
"| /usr/bin/cut -d ' ' -f1 >> /tmp/sysinfo;" );

system( "/sbin/ifconfig eth0 2> /dev/null"
"| /bin/grep -m 1 Mask: | /usr/bin/cut -d : -f4 >> /tmp/sysinfo;" );

// read ifconfig information from flat-file
const std::string TBD( "unknown" );
std::string ipAddr( TBD );
std::string broadcast( TBD );
std::string netmask( TBD );

std::ifstream sysinfo( "/tmp/sysinfo" );

if ( sysinfo )
{
if ( sysinfo.peek() != '\0' ) sysinfo >> ipAddr;
if ( sysinfo.peek() != '\0' ) sysinfo >> broadcast;
if ( sysinfo.peek() != '\0' ) sysinfo >> netmask;

sysinfo.close();

unlink( "/tmp/sysinfo" );
}

//std::cout << "IP = " << ipAddr << std::endl;
//std::cout << "BCAST = " << broadcast << std::endl;
//std::cout << "MASK = " << netmask << std::endl;

return ipAddr;

}//return main
