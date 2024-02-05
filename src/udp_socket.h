#ifndef UDPSOCKET_H
#define UDPSOCKET_H

#include <string>

enum class IP_VERSION { IPV4, IPV6 };

class UDPSocket {
 public:
  UDPSocket() = delete;
  UDPSocket(IP_VERSION version);
  bool set_iface(const std::string& interface);
  bool enable_loopback();
  bool enable_broadcast();
  IP_VERSION ip_version() const;

 private:
  int _sock_fd;
  IP_VERSION _ip_ver;
};

#endif /* UDPSOCKET_H */
