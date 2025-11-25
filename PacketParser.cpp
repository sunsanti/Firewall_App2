#include "PacketParser.h"
#include <QString>

QString PacketParser::parseSrcIP(const unsigned char* pkt) {
    // IP header bắt đầu từ byte 14 (sau Ethernet header)
    int ipHeaderStart = 14;
    return QString(
        QString::number(pkt[ipHeaderStart + 12]) + "." +
        QString::number(pkt[ipHeaderStart + 13]) + "." +
        QString::number(pkt[ipHeaderStart + 14]) + "." +
        QString::number(pkt[ipHeaderStart + 15])
    );

}

QString PacketParser::parseDstIP(const unsigned char* pkt) {
    int ipHeaderStart = 14;
    return QString(
        QString::number(pkt[ipHeaderStart + 16]) + "." +
        QString::number(pkt[ipHeaderStart + 17]) + "." +
        QString::number(pkt[ipHeaderStart + 18]) + "." +
        QString::number(pkt[ipHeaderStart + 19])
    );
}

int PacketParser::parseSrcPort(const unsigned char* pkt) {
    int ipHeaderStart = 14;
    int tcpHeaderStart = ipHeaderStart + 20; // IP header 20 byte
    return (pkt[tcpHeaderStart] << 8) + pkt[tcpHeaderStart + 1];
}

int PacketParser::parseDstPort(const unsigned char* pkt) {
    int ipHeaderStart = 14;
    int tcpHeaderStart = ipHeaderStart + 20;
    return (pkt[tcpHeaderStart + 2] << 8) + pkt[tcpHeaderStart + 3];
}
