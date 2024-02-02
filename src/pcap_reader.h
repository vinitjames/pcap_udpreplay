#ifndef PCAP_READER_H
#define PCAP_READER_H


#include <string>
#include <memory>
#include <chrono>
#include <cstdint>
#include <vector>

struct pcap_t;
enum class IP_VERSION{
  IPV4,
  IPV6,
  NOT_IP
};

struct UDPHeader{
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
};

struct UDPPayload{
  const u_char* payload;
  uint32_t length;
};

class PCAPUDPReader{
public:
  PCAPUDPReader() = delete;
  PCAPUDPReader(const std::string& filename);
  
  ~PCAPUDPReader();
  bool read_next();
  IP_VERSION ip_version() const;
  UDPHeader udp_header() const;
  UDPPayload udp_payload() const;
  std::chrono<> packet_timestamp();

  
private:
  std::vector<char> _error_buff;
  std::unique_ptr<pcap_t> _pcap_handle = nullptr;  
  const u_char* _payload_handle = nullptr;
  IP_VERSION _curr_frame_type;
};

#endif /* PCAP_READER_H */
