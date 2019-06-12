#include <iostream>
#include <net/ethernet.h>

#include "server.h"
#include "client.h"


Server::Server(const std::string & interface, const u_int8_t * localMacAddr): 
    m_interface(interface),
    m_localMacAddr(localMacAddr),
    m_pcap(nullptr){}

Server::~Server(){
    std::cout << "pcap_close" << std::endl;
    if (m_pcap != NULL){
        pcap_close(m_pcap); 
    }
}

void Server::run(){
    char errbuf[PCAP_ERRBUF_SIZE]; 

    m_pcap = pcap_open_live(m_interface.c_str(), 65535, true, 1000, errbuf);
    if(m_pcap == nullptr){
        std::cerr << "ERROR: Cannot open interface " << m_interface << ": " << errbuf << std::endl;
    }

    // 编译过滤器
    bpf_program program;
    int ret = pcap_compile(m_pcap, &program, "(ether proto 0x8625)", 1, PCAP_NETMASK_UNKNOWN);
    if(ret < 0){
        std::cerr << "ERROR: Cannot compile pcap filter (ether proto 0x8625): " << pcap_geterr(m_pcap) << std::endl;
    }

    // 设置过滤器
    ret = pcap_setfilter(m_pcap, &program);
    pcap_freecode(&program);
    if(ret < 0){
        std::cerr << "ERROR: Cannot set pcap filter (ether proto 0x8625): " << pcap_geterr(m_pcap) << std::endl;
    }

    // pcap_loop的回调
    auto callback = [](uint8_t * user, const pcap_pkthdr * pkthdr, const uint8_t * payload) {
        reinterpret_cast<const Server *>(user)->handlePacket(pkthdr, payload);
    };

    std::cout << "INFO: Server for " << m_interface << " is listening" << std::endl;

    //pcap循环抓包
    ret = pcap_loop(m_pcap, -1, callback, reinterpret_cast<uint8_t *>(this));
    if (ret < 0){
        std::cerr << "ERROR: pcap_loop error: " << pcap_geterr(m_pcap) << std::endl;
    }
}

void Server::stop(){
    pcap_breakloop(m_pcap);
    pcap_close(m_pcap);
    m_pcap = NULL;
    std::cout << "INFO: Server for " << m_interface << " stop listening" << std::endl;
}

void Server::handlePacket(const pcap_pkthdr * pkthdr, const uint8_t * payload) const {
    if(pkthdr->caplen == 0){ //捕获包的长度
        return;
    }

    if(pkthdr->len == 0){ //包应该的长度
        return;
    }
    else if(pkthdr->len < pkthdr->caplen){
        return;
    }
    else if (pkthdr->len < ETH_HLEN){
        return;
    }

    auto ether = reinterpret_cast<const ether_header *>(payload);
    const u_int8_t * destAddr = ether->ether_dhost;
    const u_int8_t * srcAddr = ether->ether_shost;

    payload += 14;
    std::string content(reinterpret_cast<const char*>(payload));

    if(isEqual(srcAddr, m_localMacAddr)){
        // std::cerr << "WARNNING: Server for "<< m_interface << " reveive frame sent by self" << std::endl;
        return;
    }

    if(isMulticast(destAddr)){
        std::cout << "INFO: Server for "<< m_interface << " reveive a multicast frame" << std::endl;

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

        Client client(m_interface, m_localMacAddr);
        client.sendAckFrame(srcAddr);
    }
    else if(isSenttoMe(destAddr)){
        std::cout << "INFO: Server for "<< m_interface << " reveive a Ack frame" << std::endl;

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
    else{
        std::cout << "WARNNING: Server for "<< m_interface << " reveive a invalid frame" << std::endl;
    }
}

bool Server::isMulticast(const uint8_t * destAddr) const {
    const uint8_t multicastAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return isEqual(destAddr, multicastAddr);
}

bool Server::isSenttoMe(const uint8_t * destAddr) const {
    return isEqual(destAddr, m_localMacAddr);
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
    cmd.append("] local dev://" + m_interface);

    system(cmd.c_str());
}