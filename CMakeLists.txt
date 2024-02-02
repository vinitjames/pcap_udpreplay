cmake_minimum_required(VERSION 3.5)    
project(udpreplay CXX)

set(CMAKE_CXX_STANDARD 11)

add_executable(pcap_udpreplay src/pcap_udpreplay.cpp)
target_compile_options(pcap_udpreplay PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_link_libraries(pcap_udpreplay pcap)

install(TARGETS udpreplay DESTINATION bin/)

