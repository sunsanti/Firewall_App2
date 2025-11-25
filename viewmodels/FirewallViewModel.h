#pragma once
#include <QObject>
#include <QVector>
#include <QtSql/QSqlDatabase>
#include "FirewallRule.h"
#include "FirewallPacket.h"
#include "PacketParser.h"

class FirewallViewModel : public QObject {
    Q_OBJECT
public:
    explicit FirewallViewModel(QObject* parent = nullptr);

    //this is the fucntion to interact with the database
    bool addRule(const FirewallRule& rule);
    bool deleteRule(int id);
    QVector<FirewallRule> loadRules();

    //This is the list of function that control the packet data flow
    QString checkPacket(const FirewallPacket &packet);

    //send verdict to main after process the packet
    static int cb_input(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* data);
    static int cb_output(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* data);
    

private:
    QSqlDatabase m_db;
    bool connectDatabase();
    int processIncoming (struct nfq_data* nfa, struct nfq_q_handle* qh);
    int processOutgoing (struct nfq_data* nfa, struct nfq_q_handle* qh);
};
