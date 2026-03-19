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

class sniffer {
    private:
    pcap_t* handler;

    public:
    void startSniffing(std::string network, std::string filter, int packet_batch);
    static void packetHandeler(u_char* args, const pcap_pkthdr* header, const u_char* packet);
};

#endif
