#include <iostream>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h> // close()

#include <thread>

#include "client.h"

Client::Client(const std::string & interface, const uint8_t * localMacAddr) : 
    m_interface(interface),
    m_localMacAddr(localMacAddr){}

Client::~Client(){}

void Client::sendMulticastFrame(){
    uint8_t dstAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    int ret = sendFrame(dstAddr, "");
    if(ret < 0){
        std::cerr << "ERROR: Client for interface " << m_interface << " failed to send multicast frame" << std::endl;
    }

    std::cout << "INFO: Client for interface " << m_interface << " sent mulicast frame to inform other route" << std::endl;
}

void Client::sendAckFrame(const u_int8_t * destAddr){
    int ret = sendFrame(destAddr, "");
    if(ret < 0){
        std::cerr << "ERROR: Client for interface " << m_interface << " failed to send ACK(unicast) frame" << std::endl;
    }

    std::cout << "INFO: Client for interface " << m_interface << " sent ACK frame" << std::endl;
}

int Client::sendFrame(const u_int8_t * destAddr, const std::string & content){
    struct sockaddr_ll device;
    memset (&device, 0, sizeof (device));
    device.sll_ifindex = if_nametoindex(m_interface.c_str());
    if(0 == device.sll_ifindex){
        std::cerr << "ERROR: Fail to get interface index" << std::endl;
        return -1;
    }

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, m_localMacAddr, 6);
    device.sll_halen = htons(6);

    uint8_t frame[ETH_ZLEN];
    memcpy (frame, destAddr, 6);
    memcpy (frame+6, m_localMacAddr, 6);
    frame[12] = 0x86;
    frame[13] = 0x25;

    size_t frameSize;
    size_t contentSize = content.size();
    size_t paddingSize = ETH_ZLEN-14;
    if(contentSize != 0){
        memcpy (frame+14, content.c_str(), contentSize);
        frameSize = 14+contentSize;
        if(contentSize < paddingSize){
            paddingSize = paddingSize-contentSize;
            memset (frame+14+contentSize, 0, paddingSize); // 填充0
            frameSize = ETH_ZLEN;
        }
    }
    else{
        memset (frame+14, 0, paddingSize); // 填充0
        frameSize = ETH_ZLEN;
    }
    

    int sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sd < 0){
        std::cerr << "ERROR: Fail to create frame socket" << std::endl;
        return -1;
    }

    size_t len = sendto(sd, frame, frameSize, 0, (struct sockaddr *)&device, sizeof (device));
    if(len != frameSize){
        std::cerr << "ERROR: The length of the sent frame is less than the actual frame" << std::endl;
        return -1;
    }

    close(sd);
    return 0;
}