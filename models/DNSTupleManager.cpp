#include "DNSTupleManager.h"

DNSTupleManager::DNSTupleManager(QObject* parent) : QObject(parent) {}

DNSTupleManager::~DNSTupleManager() {}  // ✅ phải đúng tên class

void DNSTupleManager::addTuple(const DnsTuple &tuple) {
    QWriteLocker locker(&lock);
    tuples.append(tuple);
}

bool DNSTupleManager::matchAndRemove(const QString &packetSrcIP,
                                     const QString &packetDstIP,
                                     int packetSrcPort, int packetDstPort,
                                     int protocol) {
    QWriteLocker locker(&lock);
    for(auto it = tuples.begin(); it != tuples.end(); ++it){
        const DnsTuple &t = *it;
        if(packetSrcIP == t.dstIP &&
           packetDstIP == t.srcIP &&
           packetSrcPort == t.dstPort &&
           packetDstPort == t.srcPort &&
           protocol == t.protocol) {
            tuples.erase(it);
            return true;
        }
    }
    return false;
}
