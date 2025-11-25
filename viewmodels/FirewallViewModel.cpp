#include "FirewallViewModel.h"
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDebug>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

FirewallViewModel::FirewallViewModel(QObject* parent) : QObject(parent) {
    if (!connectDatabase()) {
        qDebug() << "Database connection failed!";
    }
}

bool FirewallViewModel::connectDatabase() {
    m_db = QSqlDatabase::addDatabase("QPSQL");
    m_db.setHostName("192.168.100.90");
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
//in here dont have allow the income or deny outcome
QString FirewallViewModel::checkPacket(const FirewallPacket &packet){
    QSqlQuery query("SELECT * FROM firewall_rules");
    while(query.next()){
        QString ip = query.value(1).toString();
        int port = query.value(2).toInt();
        QString action = query.value(4).toString();
        if(packet.srcIp() == ip && (port == 0 || packet.srcPort() == port)) {
            return action;
        }
    }
    return "ALLOW";
}

static int cb_input(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* data) {
        FirewallViewModel* self = static_cast<FirewallViewModel*>(data);
        return self->processIncoming(nfa, qh);
}
    int processIncoming(struct nfq_data* nfa, struct nfq_q_handle* qh) {
        unsigned char* pktData;
        int id = nfq_get_msg_packet_hdr(nfa)->packet_id;
        int len = nfq_get_payload(nfa, &pktData);

        if(len >= 0) {
            QString srcIP = parseSrcIP(pktData);
            int srcPort = parseSrcPort(pktData);

            FirewallPacket packet(srcIP, srcPort, "", 0);
            QString result = checkPacket(packet);

            if(result == "DENY") {
                std::cout << "[IN] DROP " << srcIP.toStdString() << ":" << srcPort << "\n";
                return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
            } else {
                std::cout << "[IN] ACCEPT " << srcIP.toStdString() << ":" << srcPort << "\n";
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
            }
        }
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

