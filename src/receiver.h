#ifndef RECEIVER_H_
#define RECEIVER_H_

#include <pcap/pcap.h>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <thread>

#include "hello_protocol.h"
#include "threadpool.h"

class Receiver{
public:
    Receiver(std::set<std::string> & interfaces);
    ~Receiver();

    void run();

    void addInterface(std::string interfaceName);

    void removeInterface(const std::string & interfaceName);

private:
    bool isMulticast(const uint8_t * distAddr);
    bool isContainThisNeighbor(const uint8_t * addr);
    const char * getInterfaceName(const uint8_t * addr);
    bool isEqual(const uint8_t * addr1, const uint8_t * addr2);

    struct Interface{
        uint8_t localMacAddr[6] = {0}; // 网卡地址
        int state;
        std::unique_ptr<HelloProtocol> hello = nullptr;
    };

private:
    std::map<std::string, std::unique_ptr<Interface>> m_interfaceStore;
    std::mutex m_mutex;
    int m_socket;

    // 基础设施
    ThreadPool * m_pool;
};

#endif // RECEIVER_H_