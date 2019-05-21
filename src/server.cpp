#include <iostream>
#include <net/ethernet.h>
#include "server.h"
#include "client.h"


Server::Server(char * interface, const u_int8_t * localMacAddr): 
    m_pcap(nullptr),
    m_interface(interface),
    m_localMacAddr(localMacAddr)
{
    // std::cout << m_interface << std::endl;

    // for(int i = 0; i < 6; i++){
    //     printf ("%02x:", m_localMacAddr[i]);
    // }
    // std::cout << std::endl;
}

Server::~Server(){
    if (m_pcap){
        pcap_close(m_pcap); 
    }
}

void Server::run(){
    char errbuf[PCAP_ERRBUF_SIZE]; 

    m_pcap = pcap_open_live(m_interface, 65535, true, 1000, errbuf);
    if(m_pcap == nullptr){
        std::cerr << "Cannot open interface " << m_interface << ": " << errbuf << std::endl;
    }

    // std::string action;
    // action = "listening on " + std::string(m_interface);

    // m_dataLinkType = pcap_datalink(m_pcap);
    // const char *dltName = pcap_datalink_val_to_name(m_dataLinkType);
    // const char *dltDesc = pcap_datalink_val_to_description(m_dataLinkType);
    // std::string formattedDlt = dltName ? dltName : std::to_string(m_dataLinkType);
    // if (dltDesc){
    //     formattedDlt += "(" + std::string(dltDesc) + ")";
    // }
    // std::cout << action << ", link-type " << formattedDlt << std::endl;

    // 编译过滤器
    bpf_program program;
    int ret = pcap_compile(m_pcap, &program, "(ether proto 0x8625)", 1, PCAP_NETMASK_UNKNOWN);
    if(ret < 0){
        std::cerr << "Cannot compile pcap filter (ether proto 0x8625): " << pcap_geterr(m_pcap) << std::endl;
    }

    // 设置过滤器
    ret = pcap_setfilter(m_pcap, &program);
    pcap_freecode(&program);
    if(ret < 0){
        std::cerr << "Cannot set pcap filter (ether proto 0x8625): " << pcap_geterr(m_pcap) << std::endl;
    }

    // pcap_loop的回调
    auto callback = [](uint8_t * user, const pcap_pkthdr * pkthdr, const uint8_t * payload) {
        reinterpret_cast<const Server *>(user)->handlePacket(pkthdr, payload);
    };

    //pcap循环抓包
    ret = pcap_loop(m_pcap, -1, callback, reinterpret_cast<uint8_t *>(this));
    if (ret < 0){
        std::cerr << "pcap_loop error: " << pcap_geterr(m_pcap) << std::endl;
    }
}

void Server::handlePacket(const pcap_pkthdr * pkthdr, const uint8_t * payload) const {
    if(pkthdr->caplen == 0){ //捕获包的长度
        std::cerr << "Invalid header: caplen=0" << std::endl;
        return;
    }

    if(pkthdr->len == 0){ //包应该的长度
        std::cerr << "Invalid header: len=0" << std::endl;
        return;
    }
    else if(pkthdr->len < pkthdr->caplen){
        std::cerr << "Invalid header: len(" << pkthdr->len << ") < caplen(" << pkthdr->caplen << ")" << std::endl;
        return;
    }
    else if (pkthdr->len < ETH_HLEN){
        std::cerr << "Truncated Ethernet frame, length " << pkthdr->len << std::endl;
        return;
    }

    // if(m_dataLinkType == DLT_EN10MB){

    // }

    auto ether = reinterpret_cast<const ether_header *>(payload);

    if(isEqual(ether->ether_shost, m_localMacAddr)){ //自己发出去的帧
        return;
    }

    const u_int8_t * distAddr = ether->ether_dhost;
    const u_int8_t * srcAddr = ether->ether_dhost;
    if(isMulticast(distAddr)){
        if(!m_addrStore.empty()){
            bool isContain = false;
            for(auto & item : m_addrStore){
                if(isEqual(srcAddr, item)){
                    isContain = true;
                    break;
                }
            }
            if(!isContain){
                m_addrStore.push_back(srcAddr);
                createFace(srcAddr);
            }
        }
        else{
            m_addrStore.push_back(srcAddr);
            createFace(srcAddr);
        }

        // TODO: send ack frame
        Client client(m_interface, m_localMacAddr);
        client.sendUnicastFrame(srcAddr);
    }
    else if(isSenttoMe(distAddr)){
        if(!m_addrStore.empty()){
            bool isContain = false;
            for(auto & item : m_addrStore){
                if(isEqual(srcAddr, item)){
                    isContain = true;
                    break;
                }
            }
            if(!isContain){
                m_addrStore.push_back(srcAddr);
                createFace(srcAddr);
            }
        }
        else{
            m_addrStore.push_back(srcAddr);
            createFace(srcAddr);
        }
    }
}

bool Server::isMulticast(const uint8_t * distAddr) const {
    const uint8_t multicastAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return isEqual(distAddr, multicastAddr);
}

bool Server::isSenttoMe(const uint8_t * distAddr) const {
    return isEqual(distAddr, m_localMacAddr);
}

bool Server::isEqual(const uint8_t * addr1, const uint8_t * addr2) const {
    for(int i = 0; i < 6; i++){
        if(addr1[i] != addr2[i]){
            return false;
        }
    }
    return true;
}

void Server::createFace(const u_int8_t * macAddr) const {
    std::string cmd("nfdc face create ether://[");
    char szFormat[] = "%02X:%02X:%02X:%02X:%02X:%02X"; 
	char szMac[32] = {0};
	sprintf(szMac, szFormat, macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
	cmd.append(std::string(szMac));
    cmd.append("] local dev://" + std::string(m_interface));

    system(cmd.c_str());
}