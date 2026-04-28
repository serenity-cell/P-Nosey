cmake_minimum_required(VERSION 3.10.3)
project(P-Nosey VERSION 0.1.0 LANGUAGES C CXX)

add_executable(P-Nosey main.cpp src/sniffer.cpp)
target_link_libraries(P-Nosey pcap)

include(CTest)
enable_testing()

