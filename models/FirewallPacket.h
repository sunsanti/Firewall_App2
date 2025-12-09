#pragma once
#include <QString>

class FirewallPacket {
public:
    FirewallPacket(int id, QString srcIp, QString desIp, int srcPort, int desPort, int protocol, QString payload);

    FirewallPacket(QString srcIp, QString desIp, int srcPort, int desPort, int protocol, QString payload);

    int id() const;
    QString srcIp() const;
    QString desIp() const;
    int srcPort() const;
    int desPort() const;
    int protocol() const;
    QString payload() const;

private:
    int m_id;
    QString m_srcIp;
    QString m_desIp;
    int m_srcPort;
    int m_desPort;
    int m_protocol;
    QString m_payload;
};