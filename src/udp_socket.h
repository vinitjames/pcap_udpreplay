#ifndef UDPSOCKET_H
#define UDPSOCKET_H

#include <string>

#include "ip_version.h"

class UDPSocket {
 public:
  UDPSocket() = delete;
  UDPSocket(IP_VERSION version);
  bool set_iface(const std::string& interface);
  bool enable_loopback();
  bool enable_broadcast();
  IP_VERSION ip_version() const;
  int get_sock_fd();
  ~UDPSocket();

 private:
  int _sock_fd;
  IP_VERSION _ip_ver;
};

#endif /* UDPSOCKET_H */
