#include "pcap_reader.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

#include <iostream>
#include <stdexcept>

struct PCAPUDPReader::PCAPHandle {
 public:
  PCAPHandle() = delete;
  PCAPHandle(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    _pcap_t = pcap_open_offline_with_tstamp_precision(
        filename.c_str(), PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (_pcap_t == nullptr) {
      throw std::invalid_argument(
          "given filename could not be opened as pcap file");
    }
  }
  pcap_t* get_handle() { return _pcap_t; }

  ~PCAPHandle() { pcap_close(_pcap_t); }

 private:
  pcap_t* _pcap_t = nullptr;
};

PCAPUDPReader::PCAPUDPReader(const std::string& filename)
    : _pcap_handle{new PCAPHandle(filename)} {
  _src_ip.resize(INET6_ADDRSTRLEN + 1, '\0');
  _dst_ip.resize(INET6_ADDRSTRLEN + 1, '\0');
}

bool PCAPUDPReader::read_next() {
  bool udp_pkt_read = false;
  while (!udp_pkt_read) {
    struct pcap_pkthdr pkt_hdr;
    const u_char* pcap_payload =
        pcap_next(_pcap_handle->get_handle(), &pkt_hdr);
    if (pcap_payload == nullptr) {
      std::cout << " could not read next packet from pcap file" << std::endl;
      break;
    }
    if (_start_pkt_ts.tv_nsec == -1) {
      _start_pkt_ts.tv_sec = pkt_hdr.ts.tv_sec;
      _start_pkt_ts.tv_nsec = pkt_hdr.ts.tv_usec;
    }
    _curr_pkt_ts.tv_sec = pkt_hdr.ts.tv_sec;
    _curr_pkt_ts.tv_nsec = pkt_hdr.ts.tv_usec;
    if (pkt_hdr.len != pkt_hdr.caplen) {
      std::cout << "Pcap packet captured length not equal to actual length"
                << std::endl;
      continue;
    }
    udp_pkt_read = _parse_pcap_payload(pcap_payload);
  }
  return udp_pkt_read;
}

bool PCAPUDPReader::_parse_pcap_payload(const u_char* payload) {
  const ether_header* eth_hdr = reinterpret_cast<const ether_header*>(payload);
  switch (ntohs(eth_hdr->ether_type)) {
    case ETHERTYPE_IP:
      _curr_frame_type = IP_VERSION::IPV4;
      return _parse_ip4_pkt(payload + sizeof(ether_header));

    case ETHERTYPE_IPV6:
      _curr_frame_type = IP_VERSION::IPV6;
      return _parse_ip6_pkt(payload + sizeof(ether_header));
    default:
      std::cout << "Packet type not ipv4 or ipv6" << std::endl;
      _udp_payload = nullptr;
      return false;
  }
}

const u_char* PCAPUDPReader::udp_payload() const { return _udp_payload; }

UDPHeader PCAPUDPReader::udp_header() const { return _udp_header; }

IP_VERSION PCAPUDPReader::ip_version() const { return _curr_frame_type; }

timespec PCAPUDPReader::curr_pkt_timestamp() const { return _curr_pkt_ts; }

timespec PCAPUDPReader::start_pkt_timestamp() const { return _start_pkt_ts; }

bool PCAPUDPReader::_parse_ip4_pkt(const u_char* payload) {
  const struct ip* ipv4_header = reinterpret_cast<const struct ip*>(payload);
  if (ipv4_header->ip_v != 4) {
    std::cout << "IP Version in header is not IPV4";
    _udp_payload = nullptr;
    return false;
  }
  if (ipv4_header->ip_p != IPPROTO_UDP) {
    std::cout << "Packet payload not of type UDP";
    _udp_payload = nullptr;
    return false;
  }
  char ip4_addr[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &(ipv4_header->ip_src), ip4_addr, INET_ADDRSTRLEN) ==
      nullptr) {
    std::cout << "Could not convert ipv4 source address" << std::endl;
  }
  _src_ip = ip4_addr;
  if (inet_ntop(AF_INET, &(ipv4_header->ip_dst), ip4_addr, INET_ADDRSTRLEN) ==
      nullptr) {
    std::cout << "Could not convert ipv6 destination address" << std::endl;
  }
  _dst_ip = ip4_addr;
  return _parse_udp_pkt(payload + ipv4_header->ip_hl * 4);
}

bool PCAPUDPReader::_parse_ip6_pkt(const u_char* payload) {
  const struct ip6_hdr* ipv6_header =
      reinterpret_cast<const struct ip6_hdr*>(payload);
  if ((ipv6_header->ip6_vfc & 0xF0) != 0x60) {
    std::cout << "IP Version in header is not IPV6";
    _udp_payload = nullptr;
    return false;
  }
  if (ipv6_header->ip6_nxt != IPPROTO_UDP) {
    std::cout << "Packet payload not of type UDP";
    _udp_payload = nullptr;
    return false;
  }
  char ip6_addr[INET6_ADDRSTRLEN];
  if (inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ip6_addr,
                INET6_ADDRSTRLEN) == nullptr) {
    std::cout << "Could not convert ipv4 source address" << std::endl;
  }
  _src_ip = ip6_addr;
  if (inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ip6_addr,
                INET6_ADDRSTRLEN) == nullptr) {
    std::cout << "Could not convert ipv6 destination address" << std::endl;
  }
  _dst_ip = ip6_addr;
  return _parse_udp_pkt(payload + sizeof(ip6_hdr));
}

bool PCAPUDPReader::_parse_udp_pkt(const u_char* payload) {
  const udphdr* udp_hdr = reinterpret_cast<const udphdr*>(payload);
  _udp_header = {udp_hdr->source, udp_hdr->dest, udp_hdr->len, udp_hdr->check};
  _udp_payload = payload + sizeof(udphdr);
  return true;
}

std::string PCAPUDPReader::src_ip() const { return _src_ip; }
std::string PCAPUDPReader::dst_ip() const { return _dst_ip; }

PCAPUDPReader::~PCAPUDPReader() { delete _pcap_handle; }
