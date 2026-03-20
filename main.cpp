#include "src/sniffer.hpp"
#include <cstring>
#include <string>


void userOptions (int &arg_count, char **&arg_vector, std::string &network, std::string &filter, int &packet_batch) {
    for (int i = 1; i < arg_count; i++) {
        if (std::strcmp(arg_vector[i], "-i") == 0) {
            network = arg_vector[++i];
        }
        if (std::strcmp(arg_vector[i], "-filter") == 0) {
            filter = arg_vector[++i];
        }
        if (std::strcmp(arg_vector[i], "-range") == 0) {
            packet_batch = std::stoi(arg_vector[++i]);
        }
    }
}

int main(int arg_count, char *arg_vector[]) {
    std::string network;
    std::string filter;
    int packet_batch = -1;

    userOptions(arg_count, arg_vector, network, filter, packet_batch);

    Sniffer sniffer(network, filter, packet_batch);
    sniffer.startSniffing();


}


