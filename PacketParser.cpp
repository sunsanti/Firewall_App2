#include "PacketParser.h"
#include <QString>
#include <cstdio>

// Detect version
// bool PacketParser::isIPv4(const unsigned char* pkt) {
//     return (pkt[14] >> 4) == 4;
// }

// bool PacketParser::isIPv6(const unsigned char* pkt) {
//     return (pkt[14] >> 4) == 6;
// }

// // ---------------- IPv4 -----------------
// int PacketParser::getIPv4HeaderLen(const unsigned char* pkt) {
//     int ipHeaderStart = 14;
//     return (pkt[ipHeaderStart] & 0x0F) * 4;
// }

// QString PacketParser::parseIPv4Src(const unsigned char* pkt) {
//     int ip = 14;
//     return QString("%1.%2.%3.%4")
//         .arg(pkt[ip + 12]).arg(pkt[ip + 13])
//         .arg(pkt[ip + 14]).arg(pkt[ip + 15]);
// }

// QString PacketParser::parseIPv4Dst(const unsigned char* pkt) {
//     int ip = 14;
//     return QString("%1.%2.%3.%4")
//         .arg(pkt[ip + 16]).arg(pkt[ip + 17])
//         .arg(pkt[ip + 18]).arg(pkt[ip + 19]);
// }

// int PacketParser::parseIPv4SrcPort(const unsigned char* pkt) {
//     int ipLen = getIPv4HeaderLen(pkt);
//     int tcp = 14 + ipLen;
//     return (pkt[tcp] << 8) | pkt[tcp + 1];
// }

// int PacketParser::parseIPv4DstPort(const unsigned char* pkt) {
//     int ipLen = getIPv4HeaderLen(pkt);
//     int tcp = 14 + ipLen;
//     return (pkt[tcp + 2] << 8) | pkt[tcp + 3];
// }

// // ---------------- IPv6 -----------------
// QString PacketParser::parseIPv6Src(const unsigned char* pkt) {
//     int base = 14 + 8; // phiên bản 6, src bắt đầu byte 8 trong IPv6 header
//     char buf[40];
//     sprintf(buf,
//         "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
//         "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
//         pkt[base], pkt[base+1], pkt[base+2], pkt[base+3],
//         pkt[base+4], pkt[base+5], pkt[base+6], pkt[base+7],
//         pkt[base+8], pkt[base+9], pkt[base+10], pkt[base+11],
//         pkt[base+12], pkt[base+13], pkt[base+14], pkt[base+15]);
//     return QString(buf);
// }

// QString PacketParser::parseIPv6Dst(const unsigned char* pkt) {
//     int base = 14 + 24; // dst bắt đầu byte 24 trong IPv6 header
//     char buf[40];
//     sprintf(buf,
//         "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
//         "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
//         pkt[base], pkt[base+1], pkt[base+2], pkt[base+3],
//         pkt[base+4], pkt[base+5], pkt[base+6], pkt[base+7],
//         pkt[base+8], pkt[base+9], pkt[base+10], pkt[base+11],
//         pkt[base+12], pkt[base+13], pkt[base+14], pkt[base+15]);
//     return QString(buf);
// }

// int PacketParser::parseIPv6SrcPort(const unsigned char* pkt) {
//     int tcp = 14 + 40; // after IPv6 header
//     return (pkt[tcp] << 8) | pkt[tcp + 1];
// }

// int PacketParser::parseIPv6DstPort(const unsigned char* pkt) {
//     int tcp = 14 + 40;
//     return (pkt[tcp + 2] << 8) | pkt[tcp + 3];
// }
// Detect version trực tiếp từ đầu gói NFQUEUE
bool PacketParser::isIPv4(const unsigned char* pkt) {
    return (pkt[0] >> 4) == 4;
}

bool PacketParser::isIPv6(const unsigned char* pkt) {
    return (pkt[0] >> 4) == 6;
}

// IPv4 header length
int PacketParser::getIPv4HeaderLen(const unsigned char* pkt) {
    return (pkt[0] & 0x0F) * 4;
}

// Các hàm parse IPv4
QString PacketParser::parseIPv4Src(const unsigned char* pkt) {
    return QString("%1.%2.%3.%4")
        .arg(pkt[12]).arg(pkt[13]).arg(pkt[14]).arg(pkt[15]);
}

QString PacketParser::parseIPv4Dst(const unsigned char* pkt) {
    return QString("%1.%2.%3.%4")
        .arg(pkt[16]).arg(pkt[17]).arg(pkt[18]).arg(pkt[19]);
}

int PacketParser::parseIPv4SrcPort(const unsigned char* pkt) {
    int ipLen = getIPv4HeaderLen(pkt);
    return (pkt[ipLen]<<8) | pkt[ipLen+1];
}

int PacketParser::parseIPv4DstPort(const unsigned char* pkt) {
    int ipLen = getIPv4HeaderLen(pkt);
    return (pkt[ipLen+2]<<8) | pkt[ipLen+3];
}

// IPv6 (40 bytes header)
QString PacketParser::parseIPv6Src(const unsigned char* pkt) {
    char buf[40];
    sprintf(buf,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        pkt[8], pkt[9], pkt[10], pkt[11],
        pkt[12], pkt[13], pkt[14], pkt[15],
        pkt[16], pkt[17], pkt[18], pkt[19],
        pkt[20], pkt[21], pkt[22], pkt[23]);
    return QString(buf);
}

QString PacketParser::parseIPv6Dst(const unsigned char* pkt) {
    char buf[40];
    sprintf(buf,
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        pkt[24], pkt[25], pkt[26], pkt[27],
        pkt[28], pkt[29], pkt[30], pkt[31],
        pkt[32], pkt[33], pkt[34], pkt[35],
        pkt[36], pkt[37], pkt[38], pkt[39]);
    return QString(buf);
}

int PacketParser::parseIPv6SrcPort(const unsigned char* pkt) {
    return (pkt[40]<<8) | pkt[41];
}

int PacketParser::parseIPv6DstPort(const unsigned char* pkt) {
    return (pkt[42]<<8) | pkt[43];
}

bool PacketParser::isTCP_RST(const unsigned char* data)
{
    // ===== IPv4 =====
    if (isIPv4(data)) {
        int ihl = getIPv4HeaderLen(data);
        const unsigned char* tcp = data + ihl;

        // protocol nằm ở byte 9 của IPv4 header
        unsigned char proto = data[9];
        if (proto != 6) return false;  // not TCP

        unsigned char flags = tcp[13];
        return (flags & 0x04); // bit RST
    }

    // ===== IPv6 =====
    if (isIPv6(data)) {
        // IPv6 header fixed 40 bytes
        const unsigned char* tcp = data + 40;

        // Next Header field in IPv6 header = byte 6
        unsigned char next = data[6];
        if (next != 6) return false; // not TCP

        unsigned char flags = tcp[13];
        return (flags & 0x04); // bit RST
    }

    return false;
}


