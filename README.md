OS-Fingerprinting
=================

Objectives
----------
* Develop an OS fingerprinting tool
* Develop a tool that detects OS fingerprinting

Requirements
------------
* The tools can be developed under the OS of your choice.
* OS fingerprinting can be done using any combination of techniques.
* Use any approach that might help you avoid detection.
* Give a list of potential OS running on your opponent’s machine with a justification.
* The detection tool must print an alert when a potential fingerprinting is detected with the potential.
* IP address of the source of the attack.
* Your detection tool must not mistake legitimate traffic as a fingerprinting attempt.
* Your host must be running a web server on port 80. Extra credit if you identify the web server used by your opponent with a justification.

Overview
--------
The project consists of two main tools. The first performs OS fingerprinting for a target machine, and the second detects any attempts trying to fingerprint the running OS. The detection tool was tested against the famous tool “NMAP” and the results show that it was able to detect malicious packets and OS fingerprinting attempts, without interfering with the normal process of the running web server. The fingerprinting tool was targeted on three different machines with three different OSes and web servers. The results show that it was able to detect their operating systems as well as the installed web servers.

Attack Tool
-----------
Each Operating System (OS) has unique characteristics in its TCP/IP stack implementation that may serve to identify it on a network. There is a wide range of techniques and methods that helped us get a good estimate of the operating system running on a certain remote machine.

One approach is to use active fingerprinting. That is, special “probe” packets are sent to a certain machine, and based on its response, a certain OS is assumed.

Another approach is to use passive fingerprinting (as used in our project), where legitimate traffic is analyzed and compared for certain key differences in the TCP/IP stack implementation on different versions and types of operating systems.

This tool sends a legitimate HTTP request to the victim’s web server, and based on the response packets, different tests are applied to determine the installed OS and web server.

A total of ten techniques are used to filter out a final choice from 24 OS Versions. These techniques have different weight values based on their accuracy.

Technique | Description | Weight
:---: | :--- | :---:
**TTL** | Test the initial TTL value used by the OS | 0.5
**DF** | Some OSes set the DF bit in the IP header while others don’t | 1
**IP ID** | Different IPIDs may be sent in the IP header | 1
**Window Size** | Differentiate implementations based on default Window Size in TCP | 1
**SYN Packet Size** | May differ between different OSes | 1
**Window Scale Option (TCP)** | Not all OSes implementation use this option | 1
**TCP Options Order** | The order of TCP options may vary from one system to another | 2.5
**ACK Flag** | Differentiate OSes based on the value of the Acknowledgment Number field in the TCP header when the ACK flag is set to zero | 1
**URG flag** | Differentiate OSes based on the value of the Urgent Pointer field in the TCP header when the URG flag is set to zero | 1
**Banner Grabbing** | The HTTP reply from the web server may contain valuable information revealing the web server name and version as well as the OS name in some cases |

You can run the attack tool by issuing the following command:

> ./ofp_tool victim_ip

Detection Tool
--------------
The detector takes into consideration different kinds of attacks that may occur instantaneously or over a time interval. Upon detection of malicious behavior, the detector displays an alarm message containing the time of the attack along with the attacker’s IP and further information about the incident.

The tool first performs sanity checks on different packets (including TCP, UDP, and ICMP) to ensure correctness. More than twelve different “stateless” attacks are reported by the detector. The following shows a list of `stateless` common OS Fingerprinting attacks that are detectable:

* TCP packet with the PSH flag only set.
* TCP packet with the SYN and URG flags set.
* TCP packet with the FIN and URG flags set.
* TCP packet with the SYN, RST and URG flags set.
* TCP packet with the no flags set.
* TCP packet with the SYN and FIN flags are set.
* TCP packet with the RST and FIN flags are set.
* TCP packet with the SYN and URG flags are set.
* TCP packet with the RST and SYN flags are set.
* TCP packet with the SYN, FIN, and URG flags are set.
* TCP packet with the SYN, FIN, PUSH and URG flags are set.
* TCP packet with the SYN, ECN, CWR and URG flags are set.
* An IP packet with DF set, and containing TCP segment with the ACK flag set and advertising a window size of 1024 (common used probe).
* An IP packet with DF set, and containing TCP segment targeting a closed port with the SYN flag set and advertising a window size of 31337 (common used probe).
* An IP packet with DF set, and containing TCP segment targeting a closed port with the SYN flag set and advertising a window size of 32768 (common used probe).
* Strange options combination in TCP packet.
* ICMP Echo message with invalid code value.

A record of each client is stored at the server, where a state variable keeps info about the client’s connections from different ports to different services. A “checker” thread that runs in parallel with the main thread is used to ensure proper communication patterns as well as efficient use of resources. Therefore, the tool will be able to detect malicious behavior such as port scanning or unusual packet patterns. The following shows a list of `statefull` common OS Fingerprinting attacks that are detectable:

* Multiple TCP connection with the same source port to the same destination port is suspected as possible OS Fingerprinting.
* Multiple half-opened connection each with lifetime more than a configurable threshold is suspected as possible OS Fingerprinting.
* Port scan is suspected as possible OS Fingerprinting.
* Multiple pairs of SYN and RST TCP packets to multiple ports is suspected as possible OS Fingerprinting.

Furthermore, to protect against Banner Grabbing, the banner information in the source code of the Apache Web Server is modified, recompiled and reinstalled it. In addition, a script is written to change the Linux default TCP/IP stack parameters to avoid getting fingerprinted.

You can run the attack tool by issuing the following command:

> ./ofp_detect

References
----------
Imad Elhajj, American University of Beirut, <a href="http://staff.aub.edu.lb/~ie05/" target="_new">More</a>.
