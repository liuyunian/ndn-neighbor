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

#include "receiver.h"
#include "sender.h"
#include "util/util.h"
#include "util/macro.h"

Receiver::Receiver(std::set<std::string> & interfaces) : 
    m_pool(ThreadPool::getInstance())
{
    for(auto & item : interfaces){
        auto interface = std::make_unique<Interface>();
        getMacAddress(item, interface->localMacAddr);
        interface->state = RUN;
        auto hello = std::make_unique<HelloProtocol>(item.c_str());
        interface->hello = std::move(hello);

        m_pool->enqueue(&HelloProtocol::sendDetector, interface->hello.get(), item.c_str());

        m_interfaceStore.insert({item, std::move(interface)});
    }
}

Receiver::~Receiver(){
    close(m_socket);
}

void Receiver::run(){
    m_socket = socket(PF_PACKET, SOCK_RAW, htons(0x8625));
    if(m_socket < 0){ 
        log_fatal(FAT_SYS, "Failed to create socket in Reveive::run");
    }

    log_info("HelloRecvThread is running");

    uint8_t buffer[ETH_FRAME_LEN];
    int len;
    while(1){
        len = recvfrom(m_socket, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        if(len > 0){
            auto ether = reinterpret_cast<const ether_header *>(buffer);
            const uint8_t * destAddr = ether->ether_dhost;
            const uint8_t * srcAddr = ether->ether_shost;

            const uint8_t * payload = buffer + ETH_HLEN;

            if(isMulticast(destAddr)){
                // log_debug("Receiver get a multicast frame");

                m_mutex.lock();
                for(auto & interface : m_interfaceStore){
                    interface.second->hello->onMulicast(srcAddr, payload);
                }
                m_mutex.unlock();
            }
            else{
                // log_debug("Receiver get a Unicast frame");

                const char * interfaceName = getInterfaceName(destAddr);
                if(interfaceName != nullptr){
                    m_mutex.lock();
                    auto iter = m_interfaceStore.find(interfaceName);
                    iter->second->hello->onHello(srcAddr, payload);
                    m_mutex.unlock();
                }
            }
        }
    }
}

void Receiver::addInterface(std::string interfaceName){
    m_mutex.lock();
    auto iter = m_interfaceStore.find(interfaceName);
    if(iter != m_interfaceStore.end()){
        m_mutex.unlock();
        iter->second->state = RUN;
        return;
    }
    m_mutex.unlock();

    auto interface = std::make_unique<Interface>();
    getMacAddress(interfaceName, interface->localMacAddr);
    auto hello = std::make_unique<HelloProtocol>(interfaceName.c_str());
    interface->hello = std::move(hello);

    m_pool->enqueue(&HelloProtocol::sendDetector, interface->hello.get(), interfaceName.c_str());

    m_mutex.lock();
    m_interfaceStore.insert({interfaceName, std::move(interface)});
    m_mutex.unlock();
}

void Receiver::removeInterface(const std::string & interfaceName){
    m_mutex.lock();
    auto iter = m_interfaceStore.find(interfaceName);
    if(iter != m_interfaceStore.end()){
        iter->second->state = NON_RUN;
    }
    m_mutex.unlock();

    m_pool->enqueue([this, interfaceName]{
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));

        m_mutex.lock();
        auto iter = m_interfaceStore.find(interfaceName);
        if(iter->second->state == NON_RUN){
            iter->second->hello->onNbrOffline();
            m_interfaceStore.erase(iter);
        }
        m_mutex.unlock();
    });
}

bool Receiver::isMulticast(const uint8_t * destAddr){
    const uint8_t multicastAddr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    return isEqual(destAddr, multicastAddr);
}

const char * Receiver::getInterfaceName(const uint8_t * addr){
    m_mutex.lock();
    for(auto & item : m_interfaceStore){
        if(isEqual(addr, item.second->localMacAddr)){
            m_mutex.unlock();
            return item.first.c_str();
        }
    }
    m_mutex.unlock();
    return nullptr;
}

bool Receiver::isEqual(const uint8_t * addr1, const uint8_t * addr2){
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