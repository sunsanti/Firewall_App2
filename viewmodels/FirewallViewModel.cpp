#include "FirewallViewModel.h"
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDebug>

FirewallViewModel::FirewallViewModel(QObject* parent) : QObject(parent) {
    if (!connectDatabase()) {
        qDebug() << "Database connection failed!";
    }
}

bool FirewallViewModel::connectDatabase() {
    m_db = QSqlDatabase::addDatabase("QPSQL");
    m_db.setHostName("localhost");
    m_db.setPort(5432);
    m_db.setDatabaseName("firewall_db");
    m_db.setUserName("postgres"); // đổi tên user
    m_db.setPassword("123456"); // đổi mật khẩu

    if (!m_db.open()) {
        qDebug() << "Cannot connect to database:" << m_db.lastError().text();
        return false;
    }

    QSqlQuery query;
    query.exec("CREATE TABLE IF NOT EXISTS rules ("
               "id SERIAL PRIMARY KEY, "
               "ip VARCHAR(50), "
               "port INT, "
               "protocol VARCHAR(10), "
               "action VARCHAR(10))");

    return true;
}
bool FirewallViewModel::addRule(const FirewallRule& rule) {
    QSqlQuery query;
    query.prepare("INSERT INTO firewall_rules (ip, port, protocol, action) VALUES (:ip, :port, :protocol, :action)");

    query.bindValue(":ip", rule.ip());        // QString ok
    query.bindValue(":port", QVariant(static_cast<qlonglong>(rule.port())));
    query.bindValue(":protocol", rule.protocol());
    query.bindValue(":action", rule.action());

    if (!query.exec()) {
        qDebug() << "Insert failed:" << query.lastError().text();
        return false;
    }
    return true;
}


bool FirewallViewModel::deleteRule(int id) {
    QSqlQuery query;
    query.prepare("DELETE FROM firewall_rules WHERE id = :id");
    query.bindValue(":id", QVariant(static_cast<qlonglong>(id)));

    if (!query.exec()) {
        qDebug() << "Delete failed:" << query.lastError().text();
        return false;
    }
    return true;
}

QVector<FirewallRule> FirewallViewModel::loadRules() {
    QVector<FirewallRule> rules;
    QSqlQuery query("SELECT id, ip, port, protocol, action FROM firewall_rules");
    while (query.next()) {
        int id = query.value(0).toInt();
        QString ip = query.value(1).toString();
        int port = query.value(2).toInt();
        QString protocol = query.value(3).toString();
        QString action = query.value(4).toString();
        rules.append(FirewallRule(id, ip, port, protocol, action));
    }
    return rules;
}

//this use to handle the packet from computer to computer
bool FirewallViewModel::checkRule(const FirewallRule rule) {
    if(rule.action() == "DENY") {
        return false;
    } else {
        return true;
    }
}
void FirewallViewModel::forwardPacket(const FirewallPacket &packet) {
    qDebug() << "Forwarding to " << packet.desIp() << " port " << packet.desPort();
}
void FirewallViewModel::dropPacket(const FirewallPacket &packet) {
    qDebug() << "Dropping to " << packet.srcIp() << " port " << packet.srcPort();
}
void FirewallViewModel::handlePacket(const FirewallPacket &packet,int id) {
    QSqlQuery query;
    QString action;
    query.prepare("SELECT * FROM firewall_rules WHERE id=:id");
    query.bindValue(":id", QVariant(static_cast<qlonglong>(id)));
    query.exec();
    if (query.next()) {
        action = query.value(4).toString(); 
    }
    if(action == "DENY") {
        dropPacket(packet);
    } else {
        forwardPacket(packet);
    }
}

