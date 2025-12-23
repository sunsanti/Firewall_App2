#include "PacketParser.h"
#include <QString>
#include <cstdio>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <cstring>


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

int PacketParser::getTCPFlags(const unsigned char* pkt) {
    if (isIPv4(pkt)) {
        struct iphdr* iph = (struct iphdr*)pkt;
        if (iph->protocol != IPPROTO_TCP) return 0;

        struct tcphdr* tcph = (struct tcphdr*)(pkt + iph->ihl * 4);
        return tcph->syn << 1 | tcph->ack << 4 | tcph->rst << 2
               | tcph->fin | tcph->psh << 3 | tcph->urg << 5;
    } 
    else if (isIPv6(pkt)) {
        struct ip6_hdr* ip6h = (struct ip6_hdr*)pkt;
        // Kiểm tra next header = TCP (6)
        if (ip6h->ip6_nxt != IPPROTO_TCP) return 0;

        struct tcphdr* tcph = (struct tcphdr*)(pkt + sizeof(struct ip6_hdr));
        return tcph->syn << 1 | tcph->ack << 4 | tcph->rst << 2
               | tcph->fin | tcph->psh << 3 | tcph->urg << 5;
    }

    return 0; // không phải TCP
}


