#ifndef SERVER_H_
#define SERVER_H_

#include <pcap/pcap.h>
#include <vector>

class Server{
public:
    Server(const std::string & interface, const u_int8_t * localMacAddr);
    ~Server();

    void run();

private:
    void handlePacket(const pcap_pkthdr *pkthdr, const uint8_t * payload) const;

    bool isMulticast(const uint8_t * distAddr) const;
    bool isSenttoMe(const uint8_t * distAddr) const;
    bool isEqual(const uint8_t * addr1, const uint8_t * addr2) const;

    void createFace(const u_int8_t * macAddr) const;

private:
    std::string m_interface;
    const uint8_t * m_localMacAddr;
    pcap_t * m_pcap;

    mutable std::vector<const uint8_t *> m_addrStore;
};

#endif