#include <iostream>
#include <net/if.h>
#include <cstring>
#include <sys/ioctl.h>
#include <thread>
#include <map>
#include <set>

#include "server.h"
#include "client.h"

std::map<std::string, uint8_t *> interfaceStore;

static void
getInterfaceMacAddr(std::string interface, uint8_t * macAddr){
    struct ifreq ifreq;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    strncpy(ifreq.ifr_name, interface.c_str(), IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifreq);

    for(int i = 0; i < 6; ++ i){
        macAddr[i] = static_cast<u_int8_t>(ifreq.ifr_hwaddr.sa_data[i]);
    }
}

static void
getRunningInterface(){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t * interfaces;

	int ret = pcap_findalldevs(&interfaces, errbuf);
    if(ret < 0){
        std::cerr << "ERROR: Pacp fail to find interfaces: " << errbuf << std::endl;
		exit(1);
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
        std::cerr << "WARRNING: Pacp fail to find interfaces: " << errbuf << std::endl;
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

static void
destroyFace(const u_int8_t * macAddr){
    std::string cmd("nfdc face destroy ether://[");
    char szFormat[] = "%02X:%02X:%02X:%02X:%02X:%02X"; 
	char szMac[32] = {0};
	sprintf(szMac, szFormat, macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5]);
	cmd.append(std::string(szMac));
    cmd.append("]");

    system(cmd.c_str());
}

int main(){
   getRunningInterface();
	if(interfaceStore.empty()){
		std::cout << "INFO: Waitting for connect to other route" << std::endl;
		while(interfaceStore.empty()){
			getRunningInterface();
		}
	}
	std::cout << "INFO: Successfully get running network interface information" << std::endl;
	for(auto &item : interfaceStore){
		std::cout << "------The Mac address for " << item.first << " is ";
		for(int i = 0; i < 5; ++ i){
			printf("%2x:", item.second[i]);
		}
		printf("%2x\n", item.second[5]);
	}

    std::map<std::string, std::unique_ptr<Server>> serverStore;
	std::vector<std::thread> serverTheads;

	{
		std::vector<std::unique_ptr<Client>> clients;
		std::vector<std::thread> clientTheads;
		for(auto &item : interfaceStore){
			auto server = std::make_unique<Server>(item.first, item.second);
			std::thread serverThread(&Server::run, server.get());
			serverStore.insert({item.first, std::move(server)});
			serverTheads.push_back(std::move(serverThread));

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
            std::cout << "INFO: The interface " << interfaceName << " is running" << std::endl;

            auto macAddr = new uint8_t[6];
            getInterfaceMacAddr(interfaceName, macAddr);
            std::cout << "INFO: The Mac address for " << interfaceName << " is ";
            for(int i = 0; i < 5; ++ i){
                printf("%2x:", macAddr[i]);
            }
            printf("%2x\n", macAddr[5]);

            interfaceStore.insert({interfaceName, macAddr});

            auto server = std::make_unique<Server>(interfaceName, macAddr);
            std::thread serverThread(&Server::run, server.get());
            serverStore.insert({interfaceName, std::move(server)});
            serverTheads.push_back(std::move(serverThread));

            auto client = std::make_unique<Client>(interfaceName, macAddr);
            std::thread clientThread(&Client::sendMulticastFrame, client.get());
            clientThread.join();
        }
        else if(ret == -1){
            auto iter_interface = interfaceStore.find(interfaceName);
            interfaceStore.erase(iter_interface);

            auto iter = serverStore.find(interfaceName);
            if(iter == serverStore.end()){
                std::cerr << "ERROR: Can't find server from serverStore" << std::endl;
                exit(1);
            }

            
            for(auto &item : iter->second->m_addrStore){
                destroyFace(item); // 删除face
            }

            iter->second->stop();
            iter->second = nullptr;
            serverStore.erase(iter);
        }
    }

    for(auto &serverThead : serverTheads){
        if (serverThead.joinable()){
            serverThead.join();
        }
    }

    return 0;
}