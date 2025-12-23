#pragma once
#include <QObject>
#include <QList>
#include <QReadWriteLock>
#include <QString>

struct DnsTuple {
    QString srcIP;
    QString dstIP;
    quint16 srcPort;
    quint16 dstPort;
    quint8 protocol;

    DnsTuple(const QString &sIP, const QString &dIP, int sPort, int dPort, int proto)
        : srcIP(sIP), dstIP(dIP),
          srcPort(static_cast<quint16>(sPort)),
          dstPort(static_cast<quint16>(dPort)),
          protocol(static_cast<quint8>(proto)) {}
};

class DNSTupleManager : public QObject {
    Q_OBJECT
public:
    explicit DNSTupleManager(QObject* parent = nullptr);
    ~DNSTupleManager();

    void addTuple(const DnsTuple &tuple);
    bool matchAndRemove(const QString &packetSrcIP, const QString &packetDstIP,
                        int packetSrcPort, int packetDstPort, int protocol);

private:
    QList<DnsTuple> tuples;
    QReadWriteLock lock;
};
