#include "udp_socket.h"

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <iostream>
#include <stdexcept>

UDPSocket::UDPSocket(IP_VERSION version) {
  switch (version) {
    case IP_VERSION::IPV4: {
      _sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
      _ip_ver = IP_VERSION::IPV4;
      break;
    }
    case IP_VERSION::IPV6: {
      _sock_fd = socket(AF_INET6, SOCK_DGRAM, 0);
      _ip_ver = IP_VERSION::IPV6;
      break;
    }
  }
  if (_sock_fd == -1) {
    throw std::runtime_error("Error in socket creation");
  }
}

bool UDPSocket::set_iface(const std::string& interface) {
  unsigned int if_index = if_nametoindex(interface.c_str());
  if (if_index == 0) {
    std::cout << "Error in getting index for interface"
              << interface << std::endl;
    return false;
  }
  int sk_opt_ret;
  if (_ip_ver == IP_VERSION::IPV4) {
    struct ip_mreqn mreqn;
    mreqn.imr_ifindex = if_index;
    sk_opt_ret = setsockopt(_sock_fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn,
                            sizeof(mreqn));
  }
  if (_ip_ver == IP_VERSION::IPV6) {
    sk_opt_ret = setsockopt(_sock_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                            &if_index, sizeof(if_index));
  }
  if (sk_opt_ret == -1) {
    std::cout << "Error in setting interface for udp socket" << std::endl;
    return false;
  }
  return true;
}
bool UDPSocket::enable_loopback() {
  int enable = 1;
  int sk_opt_ret;
  if (_ip_ver == IP_VERSION::IPV4) {
    sk_opt_ret = setsockopt(_sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &enable,
                            sizeof(enable));
  }
  if (_ip_ver == IP_VERSION::IPV6) {
    sk_opt_ret = setsockopt(_sock_fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                            &enable, sizeof(enable));
  }

  if (sk_opt_ret == -1) {
    std::cout << "Error in enabling loopback for udp socket" << std::endl;
    return false;
  }
  return true;
}

bool UDPSocket::enable_broadcast() {
  int broadcast = 1;
  if (setsockopt(_sock_fd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                 sizeof(broadcast)) == -1) {
    std::cout << "Error in enabling broadcast for udp socket" << std::endl;
    return false;
  }
  return true;
}

IP_VERSION UDPSocket::ip_version() const { return _ip_ver; }
