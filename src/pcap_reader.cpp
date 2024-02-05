#include "pcap_reader.h"

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
    : _pcap_handle{new PCAPHandle(filename)} {}

bool PCAPUDPReader::read_next() {
  struct pcap_pkthdr pkt_hdr;
  const u_char* _payload_handle =
      pcap_next(_pcap_handle->get_handle(), &pkt_hdr);
  if (_payload_handle == nullptr) {
    std::cout << " could not read next packet from pcap file";
    return false;
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
    return false;
  }

  const ether_header* eth_hdr =
      reinterpret_cast<const ether_header*>(_payload_handle);
  switch (ntohs(eth_hdr->ether_type)) {
    case ETHERTYPE_IP:
      _curr_frame_type = IP_VERSION::IPV4;
      return _parse_ip4_pkt(_payload_handle + sizeof(ether_header));

    case ETHERTYPE_IPV6:
      _curr_frame_type = IP_VERSION::IPV6;
      return _parse_ip6_pkt(_payload_handle + sizeof(ether_header));
    default:
      std::cout << "Packet type not ipv4 or ipv6" << std::endl;
      _curr_frame_type = IP_VERSION::NOT_IP;
      _payload_handle = nullptr;
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
    return false;
  }
  if (ipv4_header->ip_p != IPPROTO_UDP) {
    std::cout << "Packet payload not of type UDP";
    return false;
  }
  return _parse_udp_pkt(payload + ipv4_header->ip_hl * 4);
}

bool PCAPUDPReader::_parse_ip6_pkt(const u_char* payload) {
  const struct ip6_hdr* ipv6_header =
      reinterpret_cast<const struct ip6_hdr*>(payload);
  if ((ipv6_header->ip6_vfc & 0xF0) != 0x60) {
    std::cout << "IP Version in header is not IPV6";
    return false;
  }
  if (ipv6_header->ip6_nxt != IPPROTO_UDP) {
    std::cout << "Packet payload not of type UDP";
    return false;
  }
  return _parse_udp_pkt(payload + sizeof(ip6_hdr));
}

bool PCAPUDPReader::_parse_udp_pkt(const u_char* payload) {
  if (payload == nullptr) {
    return false;
  }
  const udphdr* udp_hdr = reinterpret_cast<const udphdr*>(payload);
  _udp_header = {udp_hdr->source, udp_hdr->dest, udp_hdr->len, udp_hdr->check};
  _udp_payload = payload + sizeof(udphdr);
  return true;
}

PCAPUDPReader::~PCAPUDPReader() { delete _pcap_handle; }
