#pragma once
#include <QObject>
#include <QVector>
#include <QtSql/QSqlDatabase>
#include "FirewallRule.h"
#include "FirewallPacket.h"
#include "PacketParser.h"
#include <libnetfilter_queue/libnetfilter_queue.h>

class FirewallViewModel : public QObject {
    Q_OBJECT
public:
    explicit FirewallViewModel(QObject* parent = nullptr);

    // Database interaction
    bool addRule(const FirewallRule& rule);
    bool deleteRule(int id);
    bool updateRule(const FirewallRule& rule);
    FirewallRule getRuleById(int id);
    QVector<FirewallRule> loadRules();

    // Packet checking
    QString checkPacketIncoming(const FirewallPacket &packet, QSqlDatabase &db, bool ipv6 = false);
    QString checkPacketOutgoing(const FirewallPacket &packet, QSqlDatabase &db, bool ipv6 = false);

    // NFQUEUE callbacks
    static int cb_input(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* data);
    static int cb_output(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* data);

    //these are functions that checksum for packet
    unsigned short checksum(unsigned short *buf, int nwords);
    unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph,int tcp_len);
    void sendTcpRst(const unsigned char* pkt);

    unsigned short tcp6_checksum(struct ip6_hdr* iph, struct tcphdr* tcph);
    void sendTcpRstIPv6(const unsigned char* pkt);

private:
    QSqlDatabase m_db;

    bool connectDatabase();

    // Process packet data
    int processIncoming(struct nfq_data* nfa, struct nfq_q_handle* qh);
    int processOutgoing(struct nfq_data* nfa, struct nfq_q_handle* qh);

    // Helpers
    void logPacket(const QString &direction, const QString &ip, int port, bool ipv6, bool drop);
};
