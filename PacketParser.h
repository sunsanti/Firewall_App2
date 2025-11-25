#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <QString>

class PacketParser {
public:
    // Parse IP nguồn từ packet (IP header bắt đầu từ byte 14 nếu có Ethernet header 14 byte)
    static QString parseSrcIP(const unsigned char* pkt);

    // Parse IP đích từ packet
    static QString parseDstIP(const unsigned char* pkt);

    // Parse port nguồn (TCP/UDP header bắt đầu ngay sau IP header)
    static int parseSrcPort(const unsigned char* pkt);

    // Parse port đích
    static int parseDstPort(const unsigned char* pkt);
};

#endif // PACKETPARSER_H
