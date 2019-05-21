#ifndef SERVER_H_
#define SERVER_H_

#include <pcap/pcap.h>
#include <vector>

class Server{
public:
    Server(char * interface, const u_int8_t * localMacAddr);
    ~Server();

    void run();

private:
    void handlePacket(const pcap_pkthdr *pkthdr, const uint8_t * payload) const;

    bool isMulticast(const uint8_t * distAddr) const;
    bool isSenttoMe(const uint8_t * distAddr) const;
    bool isEqual(const uint8_t * addr1, const uint8_t * addr2) const;

    void createFace(const u_int8_t * macAddr) const;

private:
    char * m_interface;
    const uint8_t * m_localMacAddr;
    // int m_dataLinkType; // 数据链路的类型,比如以太网,无线局域网
    pcap_t * m_pcap;

    mutable std::vector<const uint8_t *> m_addrStore;
};

#endif