#ifndef HELLO_PROTOCOL_H
#define HELLO_PROTOCOL_H

#include <string>
#include <mutex>

#include "sender.h"
#include "threadpool.h"
#include "conf_file_process.h"

class HelloProtocol{
public:
    HelloProtocol(const char * interface);

    ~HelloProtocol();

    void sendDetector(const char * interface);

    void onMulicast(const u_int8_t * destAddr, const uint8_t * pkt);

    void onHello(const u_int8_t * destAddr, const uint8_t * pkt);

    void onNbrOffline();

private:
    void sendHello(const u_int8_t * destAddr);

    void dealDeadInterval();

    void encapsulateHelloPacket(uint8_t * helloPacket, u_int16_t len, u_int8_t type);

    void createFace();

    void destroyFace();

private:
    struct HelloPkt_hdr{
        u_int8_t version; // 1字节
        u_int8_t type; // 1字节
        u_int16_t pkt_len; // 2字节
        u_int32_t dead_interval; // 4字节
    };

    struct Neighbor{
        char prefix[PREFIX_MAX_SZ] = {0};
        uint8_t mac_addr[6] = {0};
        u_int32_t dead_interval = 0;
        int state = OFFLINE;
        std::mutex deadInterval_mutex;
    };

private:
    const char * m_prefix;
    const char * m_interface;
    Sender m_sender;
    Neighbor m_nbr;

    int m_curState;
    std::mutex m_curState_mutex;
    int m_timeOut_num;

    // 基础设施
    ConfFileProcessor * m_confProcessor;
    ThreadPool * m_pool;
};

#endif