#include <iostream>
#include <thread>
#include <map>

#include <sys/socket.h> // socket
#include <net/if.h> // ifreq
#include <arpa/inet.h> // htons
#include <string.h> // strncpy
#include <unistd.h> // close
#include <net/ethernet.h>
#include <assert.h> // assert

#include "server.h"
#include "client.h"

Server::Server(std::map<std::string, const uint8_t *> & interfaceStore)
{
    for(auto & item : interfaceStore){
        auto interface = std::make_unique<Interface>();
        memcpy(interface->m_localMacAddr, item.second, 6);
        auto client = std::make_unique<Client>(item.first, item.second);
        interface->m_client = std::move(client);
        m_interfaceStore.insert({item.first, std::move(interface)});
    }
}

Server::~Server(){
    close(m_socket);
}

void Server::run(){
    m_socket = socket(PF_PACKET, SOCK_RAW, htons(0x8625));
    if(m_socket < 0){ 
        std::cerr << "ERROR: Server fail to create socket" << std::endl;
        exit(1);
    }

    std::cout << "INFO: Server is listening" << std::endl;

    char buffer[ETH_FRAME_LEN];
    int len;
    while(1){
        len = recvfrom(m_socket, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        if(len > 0){
            auto ether = reinterpret_cast<const ether_header *>(buffer);
            const uint8_t * destAddr = ether->ether_dhost;
            const uint8_t * srcAddr = ether->ether_shost;

            m_mutex.lock();
            for(auto & item : m_interfaceStore){
                if(isEqual(srcAddr, item.second->m_localMacAddr)){
                    std::cerr << "WARNNING: Server for reveive a frame sent by self" << std::endl;
                    m_mutex.unlock();
                    return;
                }
            }
            m_mutex.unlock();

            if(isMulticast(destAddr)){
                std::cout << "INFO: Server reveive a multicast frame" << std::endl;

                m_mutex.lock();
                for(auto & item : m_interfaceStore){
                    item.second->m_client->sendAckFrame(srcAddr);
                }
                m_mutex.unlock();
            }
            else if(isSentToMe(destAddr)){
                std::cout << "INFO: Server reveive a Ack frame" << std::endl;

                if(!isContainThisNeighbor(srcAddr)){
                    std::string interfaceName(getInterfaceName(destAddr));
                    m_mutex.lock();
                    auto iter = m_interfaceStore.find(interfaceName);
                    memcpy(iter->second->m_neighborAddr, srcAddr, 6);
                    iter->second->m_client->sendAckFrame(srcAddr);
                    m_mutex.unlock();

                    createFace(interfaceName, srcAddr);
                }
            }
            else{
                std::cout << "WARNNING: Server reveive a invalid frame" << std::endl;
            }
        }
    }
}

void Server::addInterface(std::string & interfaceName, const uint8_t * addr){
    auto interface = std::make_unique<Interface>();
    memcpy(interface->m_localMacAddr, addr, 6);
    auto client = std::make_unique<Client>(interfaceName, addr);
    interface->m_client = std::move(client);
    m_mutex.lock();
    m_interfaceStore.insert({interfaceName, std::move(interface)});
    auto iter = m_interfaceStore.find(interfaceName);
    iter->second->m_client->sendMulticastFrame();
    m_mutex.unlock();
}

void Server::removeInterface(std::string & interfaceName){
    m_mutex.lock();
    auto iter = m_interfaceStore.find(interfaceName);
    // destroyFace(iter->second->m_neighborAddr);
    m_interfaceStore.erase(iter);
    m_mutex.unlock();
}

bool Server::isMulticast(const uint8_t * destAddr){
    const uint8_t multicastAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return isEqual(destAddr, multicastAddr);
}

bool Server::isSentToMe(const uint8_t * destAddr){
    m_mutex.lock();
    for(auto & item : m_interfaceStore){
        if(isEqual(destAddr, item.second->m_localMacAddr)){
            m_mutex.unlock();
            return true;
        }
    }
    m_mutex.unlock();
    return false;
}

bool Server::isContainThisNeighbor(const uint8_t * addr){
    m_mutex.lock();
    for(auto & item : m_interfaceStore){
        if(isEqual(addr, item.second->m_neighborAddr)){
            m_mutex.unlock();
            return true;
        }
    }
    m_mutex.unlock();
    return false;
}

const char * Server::getInterfaceName(const uint8_t * addr){
    m_mutex.lock();
    for(auto & item : m_interfaceStore){
        if(isEqual(addr, item.second->m_localMacAddr)){
            m_mutex.unlock();
            return item.first.c_str();
        }
    }
    m_mutex.unlock();
    return nullptr;
}

bool Server::isEqual(const uint8_t * addr1, const uint8_t * addr2){
    assert(addr1 != nullptr);

    if(addr2 == nullptr){
        return false;
    }

    for(int i = 0; i < 6; i++){
        if(addr1[i] != addr2[i]){
            return false;
        }
    }
    return true;
}

void Server::createFace(std::string & interface, const uint8_t * macAddr){
    std::string cmd("nfdc face create ether://[");
    char szFormat[] = "%02X:%02X:%02X:%02X:%02X:%02X"; 
	char szMac[32] = {0};
	sprintf(szMac, szFormat, macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
	cmd.append(std::string(szMac));
    cmd.append("] local dev://" + interface);

    system(cmd.c_str());
}

void Server::destroyFace(const uint8_t * macAddr){
    std::string cmd("nfdc face destroy ether://[");
    char szFormat[] = "%02X:%02X:%02X:%02X:%02X:%02X"; 
	char szMac[32] = {0};
	sprintf(szMac, szFormat, macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
	cmd.append(std::string(szMac));
    cmd.append("]");

    system(cmd.c_str());
}