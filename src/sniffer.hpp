#ifndef SNIFFER_HPP
#define SNIFFER_HPP

// libraries 
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>

class Sniffer {
    private:
    pcap_t* handler;
    std::string connection;
    std::string filter;
    int count;


    public:
    Sniffer(std::string network, std::string filter, int packet_batch);
    ~Sniffer();
    void startSniffing();
    static void packetHandeler(u_char* args, const pcap_pkthdr* header, const u_char* packet);
};

#endif
