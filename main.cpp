#include <iostream>
#include <QCoreApplication>
#include "FirewallViewModel.h"
#include <QString>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv); 
    FirewallViewModel vm;

    // giả sử id = 0 tạm thời
    // vm.addRule(FirewallRule(QString("192.168.1.1"), 22, QString("TCP"), QString("ALLOW")));
    // vm.addRule(FirewallRule(QString("10.0.0.1"), 22, QString("TCP"), QString("DENY")));

    // vm.deleteRule(2);

    for (const auto& r : vm.loadRules()) {
    std::cout << r.id() << " " 
              << r.ip().toStdString() << " "
              << r.port() << " "
              << r.protocol().toStdString() << " "
              << r.action().toStdString() << "\n";
}


    return 0;
}
