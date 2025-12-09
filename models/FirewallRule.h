#pragma once
#include <QString>

class FirewallRule {
public:
    // Dùng khi LOAD từ database
    FirewallRule(int id, QString ip, int port, int protocol, QString action, int ip_version);

    // Dùng khi ADD rule (không có id)
    FirewallRule(QString ip, int port, int protocol, QString action, int ip_version);

    FirewallRule(); // constructor mặc định

    // Getter
    int id() const;
    QString ip() const;
    int port() const;
    int protocol() const;
    QString action() const;
    int ip_version() const;

private:
    int m_id = 0;
    QString m_ip;
    int m_port = 0;
    int m_protocol = 0;
    QString m_action;
    int m_ip_version = 4;
};
