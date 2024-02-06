#ifndef IP_UTILS_H
#define IP_UTILS_H

#include <netinet/in.h>

#include <string>

namespace Utils {
struct sockaddr_in get_ipv4_addr(std::string dst_addr, uint16_t dst_port);
struct sockaddr_in6 get_ipv6_addr(std::string dst_addr, uint16_t dst_port);
uint16_t get_udp_length(uint16_t length);
}  // namespace Utils

#endif /* IP_UTILS_H */
