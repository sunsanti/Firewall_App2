#include "FirewallPacket.h"

FirewallPacket::FirewallPacket(int id, QString srcIp, QString desIp, int srcPort, int desPort, QString protocol, QString payload)
    : m_id(id), m_srcIp(srcIp), m_desIp(desIp), m_srcPort(srcPort), m_desPort(desPort), m_protocol(protocol), m_payload(payload) {}
FirewallPacket::FirewallPacket(QString srcIp, QString desIp, int srcPort, int desPort, QString protocol, QString payload)
    : m_srcIp(srcIp), m_desIp(desIp), m_srcPort(srcPort), m_desPort(desPort), m_protocol(protocol), m_payload(payload) {}

int FirewallPacket::id() const { return m_id; }
QString FirewallPacket::srcIp() const { return m_srcIp; }
QString FirewallPacket::desIp() const { return m_desIp; }
int FirewallPacket::srcPort() const { return m_srcPort; }
int FirewallPacket::desPort() const { return m_desPort; }
QString FirewallPacket::protocol() const { return m_protocol; }
QString FirewallPacket::payload() const { return m_payload; }