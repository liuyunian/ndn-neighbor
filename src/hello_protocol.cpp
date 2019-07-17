#include <thread>

#include <string.h>
#include <linux/if_ether.h>
 #include <arpa/inet.h>

#include "hello_protocol.h"
#include "util/macro.h"
#include "util/util.h"

HelloProtocol::HelloProtocol(const char * interface) :
    m_interface(interface),
    m_sender(interface),
    m_curState(ESTABLISH),
    m_timeOut_num(TIMEOUT_NUM)
{
    m_pool = ThreadPool::getInstance();
    m_confProcessor = ConfFileProcessor::getInstance();
    m_prefix = m_confProcessor->getItemContent_str("prefix");
}

HelloProtocol::~HelloProtocol(){}

void HelloProtocol::sendDetector(const char * interface){
    u_int16_t pkt_len = strlen(m_prefix) + sizeof(HelloPkt_hdr);
    uint8_t helloPacket[pkt_len];
    encapsulateHelloPacket(helloPacket, pkt_len, DETECT);

    while(m_timeOut_num > 0){
        m_sender.sendMulticastFrame(helloPacket, pkt_len); // 发送广播帧

        int timeOut = m_confProcessor->getItemContent_int("helloTimeOut", 2);
        std::this_thread::sleep_for(std::chrono::seconds(timeOut));

        m_curState_mutex.lock();
        if(m_curState == KEEP){
            m_curState_mutex.unlock();
            break;
        }
        m_curState_mutex.unlock();

        log_info("The interface for %s didn't receive ACK for Detector", interface);
        -- m_timeOut_num;
    }
}

void HelloProtocol::sendHello(const u_int8_t * destAddr){
    int helloInterval = m_confProcessor->getItemContent_int("helloInterval", 10); // 先等待一个hello interval
    std::this_thread::sleep_for(std::chrono::seconds(helloInterval));

    u_int16_t pkt_len = sizeof(HelloPkt_hdr) + strlen(m_prefix) + strlen(m_nbr.prefix);
    uint8_t helloPacket[pkt_len]; // 最大1500字节
    encapsulateHelloPacket(helloPacket, pkt_len, ASK);
    memcpy(helloPacket + sizeof(HelloPkt_hdr) + strlen(m_prefix), m_nbr.prefix, strlen(m_nbr.prefix));


    m_curState_mutex.lock();
    while(m_curState == KEEP){
        m_curState_mutex.unlock();

        m_sender.sendUnicastFrame(destAddr, helloPacket, pkt_len);
        log_info("The interface for %s send a hello packet", m_interface);

        std::this_thread::sleep_for(std::chrono::seconds(helloInterval));
    }
    m_curState_mutex.unlock();
}

void HelloProtocol::onMulicast(const u_int8_t * destAddr, const uint8_t * pkt){
    HelloPkt_hdr * hello_hdr = (HelloPkt_hdr *)pkt;
    
    u_int16_t pkt_len, pkt_ctn_len, ack_len;
    pkt_len = ntohs(hello_hdr->pkt_len); // hello包长
    pkt_ctn_len = pkt_len - sizeof(HelloPkt_hdr); // 内容长度
    ack_len = sizeof(HelloPkt_hdr) + strlen(m_prefix) + pkt_ctn_len; //响应包长度

    uint8_t ackPkt[ack_len];
    encapsulateHelloPacket(ackPkt, ack_len, DETECT);
    memcpy(ackPkt + sizeof(HelloPkt_hdr) + strlen(m_prefix), pkt + sizeof(HelloPkt_hdr), pkt_ctn_len);

    m_sender.sendUnicastFrame(destAddr, ackPkt, ack_len);
}

void HelloProtocol::onHello(const u_int8_t * destAddr, const uint8_t * pkt){
    HelloPkt_hdr * hello_hdr = (HelloPkt_hdr *)pkt;
    u_int8_t type = hello_hdr->type;
    u_int16_t pkt_len = ntohs(hello_hdr->pkt_len); // hello包长
    u_int32_t dead_interval = htonl(hello_hdr->dead_interval);

    char rtPrefix[PREFIX_MAX_SZ] = {0};
    char nbrPrefix[PREFIX_MAX_SZ] = {0};
    u_int16_t rtPrefix_len = pkt_len - sizeof(HelloPkt_hdr) - strlen(m_prefix);
    memcpy(rtPrefix, pkt + sizeof(HelloPkt_hdr), rtPrefix_len);
    memcpy(nbrPrefix, pkt + sizeof(HelloPkt_hdr) + rtPrefix_len, strlen(m_prefix));

    if(strcmp(nbrPrefix, m_prefix) != 0){ // 通过比对nbrPrefix和m_prefix判断该包是否有效
        return;
    }

    int curState = 0;
    m_curState_mutex.lock();
    curState = m_curState;
    m_curState_mutex.unlock();
    
    if(type == ACK){
        log_info("The interface for %s receive a ACK hello packet", m_interface);

        if(curState == ESTABLISH){
            m_curState_mutex.lock();
            m_curState = KEEP;
            m_curState_mutex.unlock();

            strncpy(m_nbr.prefix, rtPrefix, PREFIX_MAX_SZ);
            memcpy(m_nbr.mac_addr, destAddr, 6);
            m_nbr.dead_interval = dead_interval;
            m_nbr.state = ONLINE;

            createFace();

            m_pool->enqueue(&HelloProtocol::sendHello, this, destAddr);
            m_pool->enqueue(&HelloProtocol::dealDeadInterval, this);
        }
        else if(curState == KEEP){
            m_nbr.deadInterval_mutex.lock();
            m_nbr.dead_interval = dead_interval; // 重置dead_interval
            m_nbr.deadInterval_mutex.unlock();
        }

        return; // 不回复
    }
    else if(type == DETECT && curState == ESTABLISH){
        log_info("The interface for %s receive a DETECT hello packet", m_interface);

        m_curState_mutex.lock();
        m_curState = KEEP;
        m_curState_mutex.unlock();

        strncpy(m_nbr.prefix, rtPrefix, PREFIX_MAX_SZ);
        memcpy(m_nbr.mac_addr, destAddr, 6);
        m_nbr.dead_interval = dead_interval;
        m_nbr.state = ONLINE;

        createFace();

        m_pool->enqueue(&HelloProtocol::sendHello, this, destAddr);
        m_pool->enqueue(&HelloProtocol::dealDeadInterval, this);

        goto ack;
    }
    else if(type == ASK && curState == KEEP){
        log_info("The interface for %s receive a ASK hello packet", m_interface);
        goto ack;
    }
    else{
        return;
    }

ack:
    uint8_t ackPkt[pkt_len];
    encapsulateHelloPacket(ackPkt, pkt_len, ACK);
    memcpy(ackPkt + sizeof(HelloPkt_hdr) + strlen(m_prefix), m_nbr.prefix, strlen(m_nbr.prefix));

    m_sender.sendUnicastFrame(destAddr, ackPkt, pkt_len);
    log_info("The interface for %s send a ACK hello packet", m_interface);
}

void HelloProtocol::onNbrOffline(){
    m_curState_mutex.lock();
    if(m_curState != KEEP){
        m_curState_mutex.unlock();
        return;
    }
    m_curState = ESTABLISH; // 改变当前的状态
    m_curState_mutex.unlock();
    
    destroyFace(); // 销毁face
}

void HelloProtocol::encapsulateHelloPacket(uint8_t * helloPacket, u_int16_t len, u_int8_t type){
    memset(helloPacket, 0, len);
    HelloPkt_hdr * hello_hdr = reinterpret_cast<HelloPkt_hdr *>(helloPacket);
    hello_hdr->version = 1;
    hello_hdr->type = type;
    hello_hdr->pkt_len = htons(len);
    hello_hdr->dead_interval = htonl(m_confProcessor->getItemContent_int("deadInterval", 40));

    const char * prefix = m_confProcessor->getItemContent_str("prefix");
    memcpy(helloPacket + sizeof(HelloPkt_hdr), prefix, strlen(prefix)); // prefix
}

void HelloProtocol::dealDeadInterval(){
    while(m_nbr.state == ONLINE){
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        m_nbr.deadInterval_mutex.lock();
        -- m_nbr.dead_interval;
        if(m_nbr.dead_interval == 0){
            m_nbr.deadInterval_mutex.unlock();
            m_nbr.state = OFFLINE;
        }
        m_nbr.deadInterval_mutex.unlock();
    }

    log_info("The neighbor by interface [%s] was offline", m_interface);
    onNbrOffline();
}

void HelloProtocol::createFace(){
    std::string cmd("nfdc face create ether://[");
    char szFormat[] = "%02X:%02X:%02X:%02X:%02X:%02X"; 
	char szMac[32] = {0};
	sprintf(szMac, szFormat, m_nbr.mac_addr[0], m_nbr.mac_addr[1], m_nbr.mac_addr[2], m_nbr.mac_addr[3], m_nbr.mac_addr[4], m_nbr.mac_addr[5]);
	cmd.append(std::string(szMac));
    cmd.append("] local dev://" + std::string(m_interface));

    system(cmd.c_str());
}

void HelloProtocol::destroyFace(){
    std::string cmd("nfdc face destroy ether://[");
    char szFormat[] = "%02X:%02X:%02X:%02X:%02X:%02X"; 
	char szMac[32] = {0};
	sprintf(szMac, szFormat, m_nbr.mac_addr[0], m_nbr.mac_addr[1], m_nbr.mac_addr[2], m_nbr.mac_addr[3], m_nbr.mac_addr[4], m_nbr.mac_addr[5]);
	cmd.append(std::string(szMac));
    cmd.append("]");

    system(cmd.c_str());
}