#include <iostream>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h> // close()

// #include <chrono>
#include <thread>

#include "client.h"

Client::Client(const std::string & interface, const uint8_t * localMacAddr) : 
    m_interface(interface),
    m_localMacAddr(localMacAddr){}

Client::~Client(){}

void Client::sendMulticastFrame(){
    struct sockaddr_ll device;
    memset (&device, 0, sizeof (device));
    device.sll_ifindex = if_nametoindex(m_interface.c_str());
    if(0 == device.sll_ifindex){
        std::cerr << "ERROR: Fail to get interface index" << std::endl;
        return;
    }

    uint8_t dst_macAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, m_localMacAddr, 6);
    device.sll_halen = htons(6);

    uint8_t multicastFrame[ETH_ZLEN];
    memcpy (multicastFrame, dst_macAddr, 6);
    memcpy (multicastFrame+6, m_localMacAddr, 6);
    multicastFrame[12] = 0x86;
    multicastFrame[13] = 0x25;
    memset (multicastFrame + 14, 0, ETH_ZLEN-14); // 填充0

    int sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sd < 0){
        std::cerr << "ERROR: Fail to create multicast socket" << std::endl;
        return;
    }

    for(int i = 0; i < 3; ++ i){
        int len = sendto(sd, multicastFrame, ETH_ZLEN, 0, (struct sockaddr *)&device, sizeof (device));
        if(len != ETH_ZLEN){
            std::cerr << "ERROR: Fail to send multicaste Frame" << std::endl;
            break;
        }
        else{
            std::cout << "INFO: Client for " << m_interface << " sent a multicast frame" << std::endl;
        }

        std::chrono::milliseconds dura(50); // sleep 50ms
        std::this_thread::sleep_for(dura);
    }

    close(sd);
}

void Client::sendUnicastFrame(const u_int8_t * distAddr){
    struct sockaddr_ll device;
    memset (&device, 0, sizeof (device));
    device.sll_ifindex = if_nametoindex(m_interface.c_str());
    if(0 == device.sll_ifindex){
        std::cerr << "ERROR: Fail to get interface index" << std::endl;
        return;
    }

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, m_localMacAddr, 6);
    device.sll_halen = htons(6);

    uint8_t unicast[ETH_ZLEN];
    memcpy (unicast, distAddr, 6);
    memcpy (unicast+6, m_localMacAddr, 6);
    unicast[12] = 0x86;
    unicast[13] = 0x25;
    memset (unicast + 14, 0, ETH_ZLEN-14); // 填充0

    int sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sd < 0){
        std::cerr << "ERROR: Fail to create unicast socket" << std::endl;
        return;
    }

    int len = sendto(sd, unicast, ETH_ZLEN, 0, (struct sockaddr *)&device, sizeof (device));
    if(len != ETH_ZLEN){
        std::cerr << "ERROR: Fail to send unicast Frame" << std::endl;
    }
    else{
        std::cout << "INFO: Client for " << m_interface << " sent a unicast frame" << std::endl;
    }

    close(sd);
}