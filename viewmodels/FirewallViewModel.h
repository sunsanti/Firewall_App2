#pragma once
#include <QObject>
#include <QVector>
#include <QtSql/QSqlDatabase>
#include "FirewallRule.h"
#include "FirewallPacket.h"

class FirewallViewModel : public QObject {
    Q_OBJECT
public:
    explicit FirewallViewModel(QObject* parent = nullptr);

    //this is the fucntion to interact with the database
    bool addRule(const FirewallRule& rule);
    bool deleteRule(int id);
    QVector<FirewallRule> loadRules();

    bool checkRule(const FirewallRule rule);
    void forwardPacket(const FirewallPacket &packet);
    void dropPacket(const FirewallPacket &packet);
    void handlePacket(const FirewallPacket &packet,int id);
private:
    QSqlDatabase m_db;
    bool connectDatabase();
};
