#include <netinet/in.h>
#include <sys/socket.h>

#include <iostream>

#include "pcap_reader.h"
#include "udp_socket.h"
#include "utils.h"

int main() {
  PCAPUDPReader pcap_reader("filtered_udp.pcap");
  std::size_t pkt_no = 0;
  UDPSocket ipv4_sock{IP_VERSION::IPV4};
  UDPSocket ipv6_sock{IP_VERSION::IPV6};
  ipv6_sock.set_iface("lo");
  ipv4_sock.set_iface("lo");
  ipv6_sock.enable_loopback();
  while (pcap_reader.read_next()) {
    ssize_t bytes_sent = 0;
    UDPHeader udp_hdr = pcap_reader.udp_header();
    std::size_t udp_data_len = Utils::get_udp_length(udp_hdr.length);
    if (pcap_reader.ip_version() == IP_VERSION::IPV4) {
      struct sockaddr_in addr =
          Utils::get_ipv4_addr(pcap_reader.dst_ip(), udp_hdr.dst_port);
      bytes_sent = sendto(ipv4_sock.get_sock_fd(), pcap_reader.udp_payload(),
                          udp_data_len, 0, reinterpret_cast<sockaddr *>(&addr),
                          sizeof(addr));
    } else {
      Utils::get_ipv6_addr(pcap_reader.dst_ip(), udp_hdr.dst_port);
      struct sockaddr_in6 addr =
          Utils::get_ipv6_addr(pcap_reader.dst_ip(), udp_hdr.dst_port);
      bytes_sent = sendto(ipv6_sock.get_sock_fd(), pcap_reader.udp_payload(),
                          udp_data_len, 0, reinterpret_cast<sockaddr *>(&addr),
                          sizeof(addr));
    }
    if (bytes_sent == -1) {
      std::cout << "got error wihile sending" << std::endl;

    } else {
      std::cout << "bytes_sent: " << bytes_sent << std::endl;
    }
    std::cout << "src_ip: " << pcap_reader.src_ip()
              << " dst_ip: " << pcap_reader.dst_ip() << std::endl;
    std::cout << "packet_no: " << ++pkt_no
              << " source_port: " << udp_hdr.src_port
              << " destination_port: " << udp_hdr.dst_port << std::endl;
  }
  return 0;
}
