#include <arpa/inet.h>

#include <iostream>

#include "ip_utils.h"

namespace Utils {
struct sockaddr_in get_ipv4_addr(std::string dst_addr, uint16_t dst_port) {
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = dst_port;

  if (inet_pton(AF_INET, dst_addr.c_str(), &(addr.sin_addr)) != 1) {
    std::cout << "Could not convert ip address" << dst_addr
              << "to network address" << std::endl;
  }
  return addr;
}

struct sockaddr_in6 get_ipv6_addr(std::string dst_addr, uint16_t dst_port) {
  sockaddr_in6 addr;
  addr.sin6_family = AF_INET6;
  addr.sin6_port = dst_port;

  if (inet_pton(AF_INET6, dst_addr.c_str(), &(addr.sin6_addr)) != 1) {
    std::cout << "Could not convert ip address" << dst_addr
              << "to network address" << std::endl;
  }
  return addr;
}

uint16_t get_udp_length(uint16_t length) { return ntohs(length) - 8; }
}  // namespace Utils
