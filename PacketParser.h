#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <QString>

class PacketParser {
public:
    static bool isIPv4(const unsigned char* pkt);
    static bool isIPv6(const unsigned char* pkt);

    static QString parseIPv4Src(const unsigned char* pkt);
    static QString parseIPv4Dst(const unsigned char* pkt);

    static int parseIPv4SrcPort(const unsigned char* pkt);
    static int parseIPv4DstPort(const unsigned char* pkt);

    static QString parseIPv6Src(const unsigned char* pkt);
    static QString parseIPv6Dst(const unsigned char* pkt);

    static int parseIPv6SrcPort(const unsigned char* pkt);
    static int parseIPv6DstPort(const unsigned char* pkt);

    static int getTCPFlags(const unsigned char* pkt);

    static int getIPv4HeaderLen(const unsigned char* pkt);

    static bool isTCP_RST(const unsigned char* data);
};


#endif // PACKETPARSER_H
