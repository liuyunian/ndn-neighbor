#include <iostream>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h> // close()

#include <thread>

#include "sender.h"
#include "util/util.h"
#include "util/macro.h"

Sender::Sender(const char * interface) : 
    m_interface(interface){
    getMacAddress(m_interface, m_localMacAddr);
}

Sender::~Sender(){}

void Sender::sendMulticastFrame(uint8_t * payload, size_t len){
    if(payload == NULL || len == 0){
        log_err(ERR_NSYS, "The payload of frame can't be empty");
        return;
    }

    uint8_t destAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    int ret = sendFrame(destAddr, payload, len);
    if(ret < 0){
        log_err(ERR_NSYS, "Sender for %s failed to send a multicast frame", m_interface);
    }
    else{
        log_debug("Sender for %s sent a mulicast frame", m_interface);
    }
}

void Sender::sendUnicastFrame(const u_int8_t * destAddr, uint8_t * payload, size_t len){
    if(payload == NULL || len == 0){
        log_err(ERR_NSYS, "The payload of frame can't be empty");
        return;
    }

    int ret = sendFrame(destAddr, payload, len);
    if(ret < 0){
        log_err(ERR_NSYS, "Sender for %s failed to send a Unicast frame", m_interface);
    }
    else{
        log_debug("Sender for %s sent a Unicast frame", m_interface);
    }    
}

int Sender::sendFrame(const u_int8_t * destAddr, uint8_t * payload, size_t len){
    struct sockaddr_ll device;
    memset(&device, 0, sizeof (device));
    device.sll_ifindex = if_nametoindex(m_interface);
    if(0 == device.sll_ifindex){
        log_err(ERR_SYS, "Sender failed to get interface index");
        return -1;
    }

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, m_localMacAddr, 6);
    device.sll_halen = htons(6);

    // frame header
    uint8_t frame[ETH_FRAME_LEN];
    memcpy(frame, destAddr, 6);
    memcpy(frame + 6, m_localMacAddr, 6);
    frame[12] = 0x86;
    frame[13] = 0x25;

    // frame payload
    memcpy(frame + ETH_HLEN, payload, len);
    size_t frameSize = ETH_HLEN + len;
    if(len < (ETH_ZLEN - ETH_HLEN)){
        memset(frame + ETH_HLEN + len, 0, ETH_ZLEN - ETH_HLEN - len); // 填充0
        frameSize = ETH_ZLEN;
    }
    
    int sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sd < 0){
        log_err(ERR_SYS, "Sender failed to create frame socket");
        return -1;
    }

    size_t send_len = sendto(sd, frame, frameSize, 0, (struct sockaddr *)&device, sizeof (device));
    if(send_len != frameSize){
        log_err(ERR_NSYS, "The length of the sent frame is less than the actual frame");
        return -1;
    }

    close(sd);
    return 0;
}