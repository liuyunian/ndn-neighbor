#ifndef CLIENT_H_
#define CLIENT_H_

#include<iostream>

class Client{
public:
    Client(const char * interface, const uint8_t * localMacAddr);
    ~Client();

    void sendMulticastFrame();
    void sendUnicastFrame(const u_int8_t * distAddr);

private:
    const char * m_interface;
    const uint8_t * m_localMacAddr;
};

#endif