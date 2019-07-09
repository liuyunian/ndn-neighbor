#include <iostream>
#include <thread>
#include <mutex>
#include <map>
#include <set>
#include <vector>

#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>

#include "server.h"
#include "log/log.h"

std::map<std::string, const uint8_t *> interfaceStore;

static void
getInterfaceMacAddr(std::string interface, uint8_t * macAddr){
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

static void
getRunningInterface(){
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
            auto macAddr = new uint8_t[6];
            getInterfaceMacAddr(interfaceName, macAddr);

            interfaceStore.insert({interfaceName, macAddr});
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
            if(iter == interfaceStore.end()){ // 新加入了节点
                pcap_freealldevs(interfaces);
                return 1;
            }
        }
    }
	pcap_freealldevs(interfaces);

	if(runningInterface_num < interfaceStore.size()){ // 移除了一个节点
		for(auto & item : interfaceStore){
			auto iter = nameSet.find(item.first);
			if(iter == nameSet.end()){
				interfaceName = item.first;
				return -1;
			}
		}
	}

    return 0;
}

int main(){
   getRunningInterface();
	if(interfaceStore.empty()){
        log_info("Waitting for connect to other router");
		while(interfaceStore.empty()){
			getRunningInterface();
		}
	}

    log_info("Successfully get running network interface information");
	for(auto & interface : interfaceStore){
        log_info("------The Mac address for %s is %2x:%2x:%2x:%2x:%2x:%2x", 
                interface.first.c_str(),
                interface.second[0],
                interface.second[1],
                interface.second[2],
                interface.second[3],
                interface.second[4],
                interface.second[5]);
	}

    Server server(interfaceStore);
    std::thread serverThread(&Server::run, &server);

    {
		std::vector<std::unique_ptr<Client>> clients;
		std::vector<std::thread> clientTheads;
		for(auto &item : interfaceStore){
			auto client = std::make_unique<Client>(item.first, item.second);
			std::thread clientThread(&Client::sendMulticastFrame, client.get());
			clients.push_back(std::move(client));
			clientTheads.push_back(std::move(clientThread));
		}

		for(auto &clientThread : clientTheads){
			if (clientThread.joinable()){
				clientThread.join();
			}
		}
	}

    while(1){
        std::string interfaceName;
        int ret = listenChangeForInterface(interfaceName);

        if(ret == 1){
            log_info("The interface %s is running", interfaceName.c_str());

            auto macAddr = new uint8_t[6];
            getInterfaceMacAddr(interfaceName, macAddr);
            log_info("------The Mac address for %s is %2x:%2x:%2x:%2x:%2x:%2x", 
                    interfaceName.c_str(),
                    macAddr[0],
                    macAddr[1],
                    macAddr[2],
                    macAddr[3],
                    macAddr[4],
                    macAddr[5]);

            interfaceStore.insert({interfaceName, macAddr});
            server.addInterface(interfaceName, macAddr);
        }
        else if(ret == -1){
            log_info("The interface %s stop", interfaceName.c_str());

            auto iter_interface = interfaceStore.find(interfaceName);
            interfaceStore.erase(iter_interface);

            server.removeInterface(interfaceName);
        }
    }

    serverThread.join();

    return 0;
}