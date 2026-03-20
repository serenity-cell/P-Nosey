#include "sniffer.hpp"
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <iostream>

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

    const struct ether_header *ethernet; /* The ethernet header */
    const struct iphdr *ip; /* The IP header */
    const struct tcphdr *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    // passing on the main (this->)
    Sniffer*  self= (Sniffer*) args;

    // passes up the address of the 
    ethernet = (struct ether_header*)(packet);
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
        return;  // not IPv4, skip it
    }
    ip = (struct iphdr*)(packet + sizeof(ether_header));
    if (ip->protocol != IPPROTO_TCP) {
        return;
    }
    tcp = (struct tcphdr*)(packet + sizeof(ether_header) + ip->ihl * 4);
    payload = (char*)(packet + sizeof(ether_header) + ip->ihl * 4 + tcp->doff * 4);

    // read the packets that are wrapped by the network
    std::string source_IP = inet_ntoa(*(struct in_addr*)&ip->saddr);
    std::string dest_IP = inet_ntoa(*(struct in_addr*)&ip->daddr);
    u_int source_port = ntohs(tcp->source);
    u_int dest_port = ntohs(tcp->dest);
    int length = header->len;


    // tcp flags
    char flags[7] = "-----"; // Initialize with dashes
    if (tcp->th_flags & TH_FIN) flags[0] = 'F';
    if (tcp->th_flags & TH_SYN) flags[1] = 'S';
    if (tcp->th_flags & TH_RST) flags[2] = 'R';
    if (tcp->th_flags & TH_PUSH) flags[3] = 'P';
    if (tcp->th_flags & TH_ACK) flags[4] = 'A';
    if (tcp->th_flags & TH_URG) flags[5] = 'U';   

    std::cout << "[TCP]" <<source_IP << ":" << source_port << " -> " << dest_IP << ":" << dest_port << " length:" << length << "\n";
}