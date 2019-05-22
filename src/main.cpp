#include <iostream>
#include <net/if.h>
#include <cstring>
#include <sys/ioctl.h>
#include <thread>
#include <map>

#include "server.h"
#include "client.h"

std::map<std::string, uint8_t *> interfaceStore;

void getInterfaceMacAddr(std::string interface, uint8_t * macAddr){
    struct ifreq ifreq;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    strncpy(ifreq.ifr_name, interface.c_str(), IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifreq);

    for(int i = 0; i < 6; ++ i){
        macAddr[i] = static_cast<u_int8_t>(ifreq.ifr_hwaddr.sa_data[i]);
    }
}

void getNetworkInterface(){
    char errbuf[PCAP_ERRBUF_SIZE]; 

    pcap_if_t * interfaces;
    int ret = pcap_findalldevs(&interfaces, errbuf);
    if(ret < 0){
        std::cerr << "ERROR: Pacp fail to find interfaces: " << errbuf << std::endl;
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
    std::cout << "INFO: Successfully get running network interface information" << std::endl;
}

 bool findNewNetworkInterface(std::string & interfaceName){
    char errbuf[PCAP_ERRBUF_SIZE]; 

    pcap_if_t * interfaces;
    int ret = pcap_findalldevs(&interfaces, errbuf);
    if(ret < 0){
        std::cerr << "ERROR: Pacp fail to find interfaces: " << errbuf << std::endl;
    }

    pcap_if_t * interface;
    for(interface = interfaces; interface != NULL; interface = interface->next){
        if(interface->flags == 6 && (strcmp(interface->name, "any") != 0)){
            std::string interfaceName = std::string(interface->name);

            auto iter = interfaceStore.find(interfaceName);
            if(iter == interfaceStore.end()){
                pcap_freealldevs(interfaces);
                return true;
            }
        }
    }

    pcap_freealldevs(interfaces);
    return false;
}

int main(){
    getNetworkInterface();
    for(auto &item : interfaceStore){
        std::cout << "INFO: The Mac address for " << item.first << " is ";
        for(int i = 0; i < 5; ++ i){
            printf("%2x:", item.second[i]);
        }
        printf("%2x\n", item.second[5]);
    }

    std::vector<std::unique_ptr<Client>> clients;
    std::vector<std::unique_ptr<Server>> servers;
    std::vector<std::thread> clientTheads;
    std::vector<std::thread> serverTheads;
    for(auto &item : interfaceStore){
        auto server = std::make_unique<Server>(item.first, item.second);
        std::thread serverThread(&Server::run, server.get());
        servers.push_back(std::move(server));
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

    while(1){
        std::string interfaceName;
        if(findNewNetworkInterface(interfaceName)){
            auto macAddr = new uint8_t[6];
            getInterfaceMacAddr(interfaceName, macAddr);
            interfaceStore.insert({interfaceName, macAddr});

            std::cout << "INFO: A new interface is running" << std::endl;
            std::cout << "INFO: The Mac address for " << interfaceName << " is ";
            for(int i = 0; i < 5; ++ i){
                printf("%2x:", macAddr[i]);
            }
            printf("%2x\n", macAddr[5]);

            auto server = std::make_unique<Server>(interfaceName, macAddr);
            std::thread serverThread(&Server::run, server.get());
            servers.push_back(std::move(server));
            serverTheads.push_back(std::move(serverThread));

            auto client = std::make_unique<Client>(interfaceName, macAddr);
            std::thread clientThread(&Client::sendMulticastFrame, client.get());
            clients.push_back(std::move(client));
            clientThread.join();
        }

        std::chrono::milliseconds dura(500); // sleep 500ms
        std::this_thread::sleep_for(dura);
    }

    for(auto &serverThead : serverTheads){
        if (serverThead.joinable()){
            serverThead.join();
        }
    }

    return 0;
}