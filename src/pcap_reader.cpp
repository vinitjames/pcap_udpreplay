#include <pcap/pcap.h>

#include "pcap_reader.h"
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <stdexcept>
#include <iostream>


namespace{
  bool _parse_udp_pkt(const u_char* payload){}
  bool _parse_ip4_pkt(const u_char* payload){
    const struct ip* ipv4_header = reinterpret_cast<const struct ip*>(payload);
    if(ipv4_header->ip_v != 4){
      std::cout<< "IP Version in header is not IPV4";
      return false;
    }
    if(ipv4_header->ip_p != IPPROTO_UDP){
      std::cout<< "Packet payload not of type UDP";
      return false;
    }
    return _parse_udp_pkt(payload + ipv4_header->ip_hl*4);
  }
  bool _parse_ip6_pkt(const u_char* payload){
  }
  
}

PCAPUDPReader::PCAPUDPReader(const std::string& filename)
  :_error_buff{std::vector<char>(PCAP_ERRBUF_SIZE)},
  _pcap_handle{pcap_open_offline_with_tstamp_precision(
					  filename.c_str(),
					  PCAP_TSTAMP_PRECISION_NANO,
					  _error_buff.data())}{

  if (_pcap_handle == nullptr){
    throw std::invalid_argument("given filename could not be opened as pcap file");
  }
}

bool PCAPUDPReader::read_next(){
  std::unique_ptr<struct pcap_pkthdr> pkt_hdr{new struct pcap_pkthdr};
  _payload_handle = pcap_next(_pcap_handle.get(), pkt_hdr.get());
  if(_payload_handle == nullptr){
    std::cout << " could not read next packet from pcap file";
    return false;
  }
  if(pkt_hdr->len != pkt_hdr->caplen){
    std::cout<< "Error in pkt header len";
    return false;
  }

  const ether_header* eth_hdr  = reinterpret_cast<const ether_header*>(_payload_handle);
  switch(ntohs(eth_hdr->ether_type)){
  case ETHERTYPE_IP :
    _curr_frame_type = IP_VERSION::IPV4;
    return _parse_ip4_pkt(_payload_handle + sizeof(ether_header));
  
  case ETHERTYPE_IPV6 :
    _curr_frame_type = IP_VERSION::IPV6;
    return _parse_ip6_pkt(_payload_handle + sizeof(ether_header));
  default:
    std::cout<< "Packet type not ipv4 or ipv6"<<std::endl;
    _curr_frame_type = IP_VERSION::NOT_IP;
    _payload_handle = nullptr;
    return false;
    
   }
}

UDPPayload PCAPUDPReader::udp_payload() const{
  if(_payload_handle == nullptr){
    return {nullptr, 0};
  }
  return {_payload_handle
	  + sizeof(ether_header)
	  + get_ip_header_size()
	  + sizeof(udphdr), 0};
}

IP_VERSION PCAPUDPReader::ip_version() const {return _curr_frame_type;}
PCAPUDPReader::~PCAPUDPReader(){};
