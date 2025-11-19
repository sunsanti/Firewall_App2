#include "FirewallRule.h"

FirewallRule::FirewallRule(int id, QString ip, int port, QString protocol, QString action)
    : m_id(id), m_ip(ip), m_port(port), m_protocol(protocol), m_action(action) {}

FirewallRule::FirewallRule(QString ip, int port, QString protocol, QString action)
    : m_ip(ip), m_port(port), m_protocol(protocol), m_action(action) {}

int FirewallRule::id() const { return m_id; }
QString FirewallRule::ip() const { return m_ip; }
int FirewallRule::port() const { return m_port; }
QString FirewallRule::protocol() const { return m_protocol; }
QString FirewallRule::action() const { return m_action; }
