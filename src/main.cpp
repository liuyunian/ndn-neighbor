#include <iostream>
#include <net/if.h>
#include <cstring>
#include <sys/ioctl.h>
#include <thread>

#include "server.h"
#include "client.h"


char * getNetworkDevice(){
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_if_t * alldevs;
    int ret = pcap_findalldevs(&alldevs,errbuf);
    if(ret < 0){
        std::cerr << errbuf << std::endl;
        return NULL;
    }

    return alldevs->name; // 默认取第一个dev
}

void getLocalMacAddr(char * interface, uint8_t * macAddr){
    struct ifreq ifreq;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    strncpy(ifreq.ifr_name, interface, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifreq);

    for(int i = 0; i < 6; i++){
        macAddr[i] = static_cast<u_int8_t>(ifreq.ifr_hwaddr.sa_data[i]);
        // printf ("%02x:", m_macAddr[i]);
    }
}

int main(){
    char * interface = getNetworkDevice();
    if(NULL == interface){
        return -1;   
    }

    uint8_t localMacAddr[6];
    getLocalMacAddr(interface, localMacAddr);

    Server server(interface, localMacAddr);
    Client client(interface, localMacAddr);

    std::thread serverThread(&Server::run, &server);
    std::thread clientThread(&Client::sendMulticastFrame, &client);

    serverThread.join();
    clientThread.join();

    return 0;
}