#ifndef SENDER_H_
#define SENDER_H_

#include<string>

class Sender{
public:
    Sender(const char * interface);
    ~Sender();

    void sendMulticastFrame(uint8_t * payload, size_t len);
    void sendUnicastFrame(const u_int8_t * distAddr, uint8_t * payload, size_t len);

private:
    int sendFrame(const u_int8_t * distAddr, uint8_t * payload, size_t len);

private:
    const char * m_interface;
    uint8_t m_localMacAddr[6];
};

#endif