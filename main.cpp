#include "src/sniffer.hpp"
#include <cstring>
#include <string>


void userOptions (int &arg_count, char **&arg_vector, std::string &network, std::string &filter, int &packet_batch) {
    if (std::strcmp(arg_vector[1], "-man") == 0 ) {
        std::cout << "\nUsage: ./P-Nosey -i [network connection (lo, wlp.... ,etc)] -fitler ['udp' or 'tcp'] -range [how many pakcets to sniff before ending. default: -1 aka. infinite]\n"
                << "DO NOTE YOU WILL HAVE TO 'cmake build ..' AND 'cd build' IN THAT ORDER BEFORE USING P-NOSEY."
                << "NOTE: THIS SERVICE POTENTIALLY REQUIRES ROOT PRIVILIGES"; 
    }
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

    if (std::strcmp(arg_vector[1], "-man") != 0) {
        Sniffer sniffer(network, filter, packet_batch);
        std::cout << "              SOURCE                  ->    DESTINATION            PACKET SIZE \n"
              << "---------------------------------------------------------------------------\n";
        sniffer.startSniffing();
    }


}


