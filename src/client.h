#ifndef CLIENT_H_
#define CLIENT_H_

#include<string>

class Client{
public:
    Client(const std::string & interface, const uint8_t * localMacAddr);
    ~Client();

    void sendMulticastFrame();
    void sendAckFrame(const u_int8_t * distAddr);

private:
    int sendFrame(const u_int8_t * distAddr, const std::string & content);

private:
    std::string m_interface;
    const uint8_t * m_localMacAddr;
    std::string m_prefix;
};

#endif