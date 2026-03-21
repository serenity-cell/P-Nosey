#include "sniffer.hpp"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>  
#include <iostream>
#include <iomanip>

#include <pcap/pcap.h>

Sniffer::Sniffer(std::string network, std::string bpf_filter, int packet_batch) {
    connection = network;
    sniffer_filter = bpf_filter;
    count = packet_batch;
    handler = nullptr;
}

Sniffer::~Sniffer() {
    if (handler != nullptr) {
        pcap_close(handler);
    }
}


void Sniffer::startSniffing() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program compiledFilter;

    handler = pcap_open_live(connection.c_str(), 65535, 1, 1000, errorBuffer);
    if (handler == nullptr) {
        std::cerr << "open_live failed: " << errorBuffer << "\n";
        return;
    }


    int compile = pcap_compile(handler, &compiledFilter, sniffer_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN);
    if (compile == -1) {
        std::cout << "compiler failed";
        return;
    } 

    int set_filter = pcap_setfilter(handler, &compiledFilter);
    if (set_filter == -1) {
        std::cout << "set_filter failed";
        return;
    }


    pcap_loop(handler, count, packetHandeler, (u_char*) this);
    pcap_freecode(&compiledFilter);

}

void Sniffer::packetHandeler(u_char *args, const pcap_pkthdr *header, const u_char *packet) {
    // TODO: implement DRY 
    // declaring headers
    const struct ether_header *ethernet;
    const struct iphdr *ip;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    const char *payload; 

    // packet reading declerations
    std::string source_IP;
    std::string dest_IP;
    u_int source_port;
    u_int dest_port;
    int length;

    // passing on the main (this->)
    Sniffer*  self= (Sniffer*) args;

    // passes up the address of the 
    ethernet = (struct ether_header*)(packet);
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
        return;  // not IPv4, skip it
    }

    ip = (struct iphdr*)(packet + sizeof(ether_header));
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr*)(packet + sizeof(ether_header) + ip->ihl * 4);
        payload = (char*)(packet + sizeof(ether_header) + ip->ihl * 4 + tcp->doff * 4);

        source_port = ntohs(tcp->source);
        dest_port = ntohs(tcp->dest);
        length = header->len;
        
    }
    else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr*)(packet + sizeof(ether_header) + ip->ihl * 4);

        // read the packets that are wrapped by the network
        source_port = ntohs(udp->source);
        dest_port = ntohs(udp->dest);
        length = header->len;
    
    }
    else {
        return;
    }
   
    source_IP = inet_ntoa(*(struct in_addr*)&ip->saddr);
    dest_IP = inet_ntoa(*(struct in_addr*)&ip->daddr);
    if (ip->protocol == IPPROTO_TCP) {
        // tcp flags
        char flags[7] = "-----"; // Initialize with dashes
        if (tcp->th_flags & TH_FIN) flags[0] = 'F';
        if (tcp->th_flags & TH_SYN) flags[1] = 'S';
        if (tcp->th_flags & TH_RST) flags[2] = 'R';
        if (tcp->th_flags & TH_PUSH) flags[3] = 'P';
        if (tcp->th_flags & TH_ACK) flags[4] = 'A';
        if (tcp->th_flags & TH_URG) flags[5] = 'U';   

        std::cout << std::left
        << std::setw(6) << "[TCP] "
        << std::setw(6) << flags
        << std::setw(15) << source_IP 
        << " : "   
        << std::setw(5) << source_port
        << " -> "
        << std::setw(15) << dest_IP
        << " : "
        << std::setw(7) << dest_port
        << std::setw(8) << " length: "
        << std::setw(13) << length 
        << std::endl;
    }
    else if (ip->protocol == IPPROTO_UDP) {
        std::cout << std::left
        << std::setw(12) << "[UDP] "
        << std::setw(15) << source_IP 
        << " : "   
        << std::setw(5) << source_port
        << " -> "
        << std::setw(15) << dest_IP
        << " : "
        << std::setw(7) << dest_port
        << std::setw(8) << " length: "
        << std::setw(13) << length 
        << std::endl;
    }
} 