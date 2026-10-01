#pragma once
/**
 * network/packet_parser.hpp — Parse Ethernet > IP > TCP/UDP
 *
 * Fast path: pointeurs directs, pas de memcpy, endianness convertie au besoin.
 */
#include <stdint.h>
#include <string>
#include <arpa/inet.h>

namespace logsoc {

/* ── Ethernet ── */
#pragma pack(push, 1)
struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;    // Host endianness
};
#pragma pack(pop)

/* ── IPv4 ── */
#pragma pack(push, 1)
struct ipv4_hdr {
    uint8_t  ihl_version;      // upper 4 = version, lower 4 = ihl*4
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};
#pragma pack(pop)

/* ── IPv6 ── */
#pragma pack(push, 1)
struct ipv6_hdr {
    uint32_t ver_tc_fl;    // 4b ver | 8b tc | 20b flow
    uint16_t payload_len;
    uint8_t  next_header;  // IPPROTO_TCP/UDP
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
};
#pragma pack(pop)

/* ── TCP ── */
#pragma pack(push, 1)
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off_flags; // 4b data_off*4, 6b reserved, 6b flags → non, c'est:
                            // first nibble = data_off>>2, reste = flags
    uint8_t  flags;          // CWR,ECE,URG,ACK,PSH,RST,SYN,FIN
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};
#pragma pack(pop)

/* ── UDP ── */
#pragma pack(push, 1)
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
#pragma pack(pop)

// TCP flag bits
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;
constexpr uint8_t TCP_ECE = 0x40;
constexpr uint8_t TCP_CWR = 0x80;

// EtherType
constexpr uint16_t ETHERTYPE_IP   = 0x0800;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

// IP proto — may already be defined by system headers (netdb.h on musl)
#ifndef IPPROTO_TCP
constexpr uint8_t IPPROTO_TCP  = 6;
#endif
#ifndef IPPROTO_UDP
constexpr uint8_t IPPROTO_UDP  = 17;
#endif
#ifndef IPPROTO_ICMP
constexpr uint8_t IPPROTO_ICMP = 1;
#endif

static inline uint16_t ntoh16(uint16_t v) {
    return (v >> 8) | (v << 8);
}
static inline uint32_t ntoh32(uint32_t v) {
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8)
         | ((v >> 8) & 0xFF00) | (v >> 24);
}

struct parsed_packet {
    bool     valid = false;
    bool     is_ipv4 = false;
    bool     is_ipv6 = false;
    uint64_t timestamp_us;
    char     src_ip[46] = {};
    char     dst_ip[46] = {};
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  proto = 0;     // IPPROTO_TCP/UDP/ICMP
    uint8_t  tcp_flags = 0; // valide si proto == TCP
    const uint8_t* payload_start = nullptr; // pointeur DANS le pcap frame
    uint16_t payload_len = 0;  // taille frame
    uint16_t payload_total = 0; // taille totale IP payload si dispo
};

/**
 * Parse un frame capturé par pcap.
 * data: pointeur vers les données brutes du frame (incluant Ethernet)
 * caplen: longueur capturée (snaplen)
 */
inline parsed_packet parse_packet(const uint8_t* data, uint32_t caplen, uint64_t ts_us) {
    parsed_packet pkt;
    if (caplen < sizeof(eth_hdr)) return pkt;

    const eth_hdr* eth = reinterpret_cast<const eth_hdr*>(data);
    uint16_t etype = ntoh16(eth->type);
    uint32_t ip_offset = sizeof(eth_hdr);
    uint16_t ip_payload_len = 0;

    if (etype == ETHERTYPE_IP) {
        if (caplen < ip_offset + sizeof(ipv4_hdr)) return pkt;
        const ipv4_hdr* ip = reinterpret_cast<const ipv4_hdr*>(data + ip_offset);
        uint8_t header_len = (ip->ihl_version & 0x0F) * 4;
        uint32_t total_ip   = ntoh16(ip->total_len);
        // VULN-033: integer overflow / underflow validation
        if (header_len < 20 || header_len > 60 || total_ip < header_len || total_ip > caplen) {
            return pkt; // malformed IP header
        }

        // IP source → char[46] (sized for IPv6 dotted-quad notated as
        // "::ffff:255.255.255.255" = 45 chars + null; see struct field).
        // For IPv4 ("%u.%u.%u.%u") snprintf produces 15 chars + null, so
        // the actual write fits well within the buffer. The size param
        // uses sizeof(pkt.src_ip) instead of a hardcoded 16 so future
        // format-string changes (e.g. adding a prefix) can't silently
        // overflow — T12.13 (audit Nova H-05).
        uint32_t src = ntoh32(ip->src);
        uint32_t dst = ntoh32(ip->dst);
        snprintf(pkt.src_ip, sizeof(pkt.src_ip), "%u.%u.%u.%u",
                 (src >> 24) & 0xFF, (src >> 16) & 0xFF,
                 (src >> 8)  & 0xFF,  src        & 0xFF);
        snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "%u.%u.%u.%u",
                 (dst >> 24) & 0xFF, (dst >> 16) & 0xFF,
                 (dst >> 8)  & 0xFF,  dst        & 0xFF);
        pkt.proto = ip->proto;
        ip_payload_len = total_ip - header_len;
        ip_offset += header_len;

        if (caplen < ip_offset + sizeof(tcp_hdr) && pkt.proto == IPPROTO_TCP) return pkt;
        if (caplen < ip_offset + sizeof(udp_hdr) && pkt.proto == IPPROTO_UDP)  return pkt;

        pkt.is_ipv4 = true;

    } else if (etype == ETHERTYPE_IPV6) {
        if (caplen < ip_offset + sizeof(ipv6_hdr)) return pkt;
        const ipv6_hdr* ip = reinterpret_cast<const ipv6_hdr*>(data + ip_offset);
        // Simplifié: juste next_header (chaining pas géré ici)
        if (ip->next_header != IPPROTO_TCP && ip->next_header != IPPROTO_UDP) {
            // Skip extension headers basique
            return pkt;
        }
        // IPv6 addr format
        inet_ntop(AF_INET6, ip->src, pkt.src_ip, 46);
        inet_ntop(AF_INET6, ip->dst, pkt.dst_ip, 46);
        pkt.proto = ip->next_header;
        ip_payload_len = ntoh16(ip->payload_len);
        ip_offset += sizeof(ipv6_hdr);

        pkt.is_ipv6 = true;
    } else {
        return pkt;  // Non-IP → on drop
    }

    // L4
    if (pkt.proto == IPPROTO_TCP) {
        const tcp_hdr* tcp = reinterpret_cast<const tcp_hdr*>(data + ip_offset);
        uint8_t data_off = (tcp->data_off_flags >> 4) * 4; // en fait c'est mal packé sur cette machine...
        // Correction: en x86_64 little-endian, le struct pack n'est pas garanti.
        // On lit raw bytes:
        uint8_t doff = data[ip_offset + 12] >> 4; // TCP data offset est upper 4 bits de byte 12
        data_off = doff * 4;

        pkt.src_port = ntoh16(tcp->src_port);
        pkt.dst_port = ntoh16(tcp->dst_port);
        pkt.tcp_flags = data[ip_offset + 13]; // TCP flags byte
        ip_offset += data_off;
    } else if (pkt.proto == IPPROTO_UDP) {
        const udp_hdr* udp = reinterpret_cast<const udp_hdr*>(data + ip_offset);
        pkt.src_port = ntoh16(udp->src_port);
        pkt.dst_port = ntoh16(udp->dst_port);
        ip_offset += sizeof(udp_hdr);
    } /* ICMP: no ports */

    pkt.payload_start = data + ip_offset;
    uint32_t remaining = (caplen > ip_offset) ? (caplen - ip_offset) : 0;
    // Ne prendre que ip_payload_len max (pas snaplen si snaplen est plus grand)
    uint16_t max_pay = (ip_payload_len < remaining) ? ip_payload_len : remaining;
    pkt.payload_len = (max_pay < 65535) ? max_pay : 65535;
    pkt.payload_total = ip_payload_len;
    pkt.timestamp_us = ts_us;
    pkt.valid = true;
    return pkt;
}

} // namespace logsoc
