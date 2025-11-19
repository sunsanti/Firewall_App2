#pragma once
#include <QString>

class FirewallRule {
public:
    FirewallRule(int id, QString ip, int port, QString protocol, QString action);

    FirewallRule(QString ip, int port, QString protocol, QString action);

    int id() const;
    QString ip() const;
    int port() const;
    QString protocol() const;
    QString action() const;

private:
    int m_id;
    QString m_ip;
    int m_port;
    QString m_protocol;
    QString m_action;
};
