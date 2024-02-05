#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <time.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

enum class IP_VERSION { IPV4, IPV6, NOT_IP };

struct UDPHeader {
  uint16_t src_port;  // all values in network byte order
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
};

class PCAPUDPReader {
 public:
  PCAPUDPReader() = delete;
  PCAPUDPReader(const std::string& filename);

  ~PCAPUDPReader();
  bool read_next();
  IP_VERSION ip_version() const;
  UDPHeader udp_header() const;
  const u_char* udp_payload() const;
  timespec curr_pkt_timestamp() const;
  timespec start_pkt_timestamp() const;

 private:
  struct PCAPHandle;
  PCAPHandle* _pcap_handle = nullptr;
  const u_char* _udp_payload = nullptr;
  UDPHeader _udp_header;
  IP_VERSION _curr_frame_type;
  struct timespec _start_pkt_ts = {-1, -1};
  struct timespec _curr_pkt_ts;

  bool _parse_ip4_pkt(const u_char* payload);
  bool _parse_ip6_pkt(const u_char* payload);
  bool _parse_udp_pkt(const u_char* payload);
};

#endif /* PCAP_READER_H */
