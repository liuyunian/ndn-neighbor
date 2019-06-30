#ifndef SERVER_H_
#define SERVER_H_

#include <pcap/pcap.h>
#include <map>
#include <memory>
#include <mutex>

#include "client.h"

class Server{
public:
    Server(std::map<std::string, const uint8_t *> & interfaceStore);
    ~Server();

    void run();

    void addInterface(std::string & interface, const uint8_t * addr);

    void removeInterface(std::string & interfaceName);

private:
    bool isMulticast(const uint8_t * distAddr);
    bool isSentToMe(const uint8_t * distAddr);
    bool isEqual(const uint8_t * addr1, const uint8_t * addr2);
    bool isContainThisNeighbor(const uint8_t * addr);
    const char * getInterfaceName(const uint8_t * addr);

    void createFace(std::string & interface, const u_int8_t * macAddr);
    void destroyFace(const uint8_t * macAddr);

    struct Interface{
        uint8_t m_localMacAddr[6];
        uint8_t m_neighborAddr[6];
        std::unique_ptr<Client> m_client = nullptr;
    };

private:
    std::map<std::string, std::unique_ptr<Interface>> m_interfaceStore;
    std::mutex m_mutex;
    int m_socket;
};

#endif