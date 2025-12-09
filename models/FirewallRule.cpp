#include "FirewallRule.h"

FirewallRule::FirewallRule(int id, QString ip, int port, int protocol, QString action, int ip_verison)
    : m_id(id), m_ip(ip), m_port(port), m_protocol(protocol), m_action(action), m_ip_version(ip_verison) {}

FirewallRule::FirewallRule(QString ip, int port, int protocol, QString action, int ip_verison)
    : m_ip(ip), m_port(port), m_protocol(protocol), m_action(action), m_ip_version(ip_verison) {}

FirewallRule::FirewallRule()
    : m_id(0), m_ip(""), m_port(0), m_protocol(0), m_action(""), m_ip_version(4)
{
}


int FirewallRule::id() const { return m_id; }
QString FirewallRule::ip() const { return m_ip; }
int FirewallRule::port() const { return m_port; }
int FirewallRule::protocol() const { return m_protocol; }
QString FirewallRule::action() const { return m_action; }
int FirewallRule::ip_version() const { return m_ip_version; }
