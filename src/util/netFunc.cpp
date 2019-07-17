/**
 * 放置与网络相关的函数
*/
#include <string>

#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>

#include "util.h"
#include "macro.h"

void getMacAddress(std::string interface, uint8_t * macAddr){
    struct ifreq ifreq;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        log_fatal(FAT_SYS, "Fail to create socket in getInterfaceMacAddr");
    }

    strncpy(ifreq.ifr_name, interface.c_str(), IFNAMSIZ);
    int err = ioctl(sock, SIOCGIFHWADDR, &ifreq);
    if(err){
        log_fatal(FAT_SYS, "Fail to get Mac Addr by ioctl");
    }

    for(int i = 0; i < 6; ++ i){
        macAddr[i] = static_cast<uint8_t>(ifreq.ifr_hwaddr.sa_data[i]);
    }
}