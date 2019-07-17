#include <iostream>
#include <thread>
#include <mutex>
#include <map>
#include <set>
#include <vector>

#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>

#include "receiver.h"
#include "util/util.h"
#include "util/macro.h"
#include "threadpool.h"
#include "conf_file_process.h"

static std::set<std::string> interfaceStore;

static void
initInterfaceStore(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * interfaces;

	int ret = pcap_findalldevs(&interfaces, errbuf);
    if(ret < 0){
        log_fatal(FAT_NSYS, "Pacp fail to find interfaces: %s", errbuf);
    }

	pcap_if_t * interface;
    for(interface = interfaces; interface != NULL; interface = interface->next){
        if(interface->flags == 6 && (strcmp(interface->name, "any") != 0)){
            std::string interfaceName(interface->name);
            interfaceStore.insert(interfaceName);
        }
    }

    pcap_freealldevs(interfaces);
}

static int
listenChangeForInterface(std::string & interfaceName){
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * interfaces;

	int ret = pcap_findalldevs(&interfaces, errbuf);
    if(ret < 0){
        log_err(ERR_NSYS, "Pacp fail to find interfaces: %s", errbuf);
		return 2;
    }

    pcap_if_t * interface;
	size_t runningInterface_num = 0;
	std::set<std::string> nameSet;
    for(interface = interfaces; interface != NULL; interface = interface->next){
        if(interface->flags == 6 && (strcmp(interface->name, "any") != 0)){
			++ runningInterface_num;
            interfaceName = std::string(interface->name);
			nameSet.insert(interfaceName);

            auto iter = interfaceStore.find(interfaceName);
            if(iter == interfaceStore.end()){
                pcap_freealldevs(interfaces);
                return 1;
            }
        }
    }
	pcap_freealldevs(interfaces);

	if(runningInterface_num < interfaceStore.size()){
		for(auto & item : interfaceStore){
			auto iter = nameSet.find(item);
			if(iter == nameSet.end()){
				interfaceName = item;
				return -1;
			}
		}
	}

    return 0;
}

int main(){
    // 读取配置文件
    ConfFileProcessor * confProcessor = ConfFileProcessor::getInstance();
    if(!confProcessor->load("autoFace.conf")){
        log_fatal(FAT_NSYS, "Failed to load %s, exit", "autoFace.conf");
    }

    // 设置log级别
    log_set_level(LOG_INFO);

    ThreadPool * pool = ThreadPool::getInstance(); // 保证了线程安全

    initInterfaceStore();
	if(interfaceStore.empty()){
        log_info("Waitting for connect to other router");
		while(interfaceStore.empty()){
			initInterfaceStore();
		}
	}

    Receiver receiver(interfaceStore);
    std::thread serverThread(&Receiver::run, &receiver);

    while(1){
        std::string interfaceName;
        int ret = listenChangeForInterface(interfaceName);

        if(ret == 1){
            log_info("The interface %s is running", interfaceName.c_str());

            interfaceStore.insert(interfaceName);
            receiver.addInterface(interfaceName);
        }
        else if(ret == -1){
            log_info("The interface %s stop", interfaceName.c_str());

            auto iter = interfaceStore.find(interfaceName);
            interfaceStore.erase(iter);
            receiver.removeInterface(interfaceName);  
        }
    }

    serverThread.join();

    return 0;
}