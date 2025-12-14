#include "FirewallViewModel.h"
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QDebug>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <iostream> 
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

enum ConnState { NEW, ESTABLISHED, RELATED };

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
    m_db.setUserName("postgres");
    m_db.setPassword("123456");

    if (!m_db.open()) {
        qDebug() << "Cannot connect to database:" << m_db.lastError().text();
        return false;
    }

    QSqlQuery query;
    // Thêm ip_version vào database
    query.exec("CREATE TABLE IF NOT EXISTS firewall_rules ("
               "id SERIAL PRIMARY KEY, "
               "ip VARCHAR(50), "
               "port INT, "
               "protocol VARCHAR(10), "
               "action VARCHAR(10), "
               "ip_version INT)"); // 4=IPv4, 6=IPv6

    return true;
}
bool FirewallViewModel::addRule(const FirewallRule& rule) {
    QSqlQuery query;

    // Nếu chỉ nhập port (IP rỗng), tạo 2 row mặc định cho IPv4 và IPv6
    if(rule.ip().isEmpty() && rule.port() != 0) {
        // IPv4 default IP
        query.prepare("INSERT INTO firewall_rules (ip, port, protocol, action, ip_version) "
                      "VALUES (:ip, :port, :protocol, :action, :ip_version)");
        query.bindValue(":ip", "0.0.0.0");
        query.bindValue(":port", QVariant(static_cast<qlonglong>(rule.port())));
        int proto4 = rule.protocol();   // giờ là số
        query.bindValue(":protocol", proto4);
        query.bindValue(":action", rule.action());
        query.bindValue(":ip_version", 4);
        if(!query.exec()) {
            qDebug() << "Insert failed:" << query.lastError().text();
            return false;
        }

        // IPv6 default IP
        query.prepare("INSERT INTO firewall_rules (ip, port, protocol, action, ip_version) "
                      "VALUES (:ip, :port, :protocol, :action, :ip_version)");
        query.bindValue(":ip", "::/0");
        query.bindValue(":port", QVariant(static_cast<qlonglong>(rule.port())));
        int proto6 = rule.protocol();   // giờ là số
        query.bindValue(":protocol", proto6);
        query.bindValue(":action", rule.action());
        query.bindValue(":ip_version", 6);
        if(!query.exec()) {
            qDebug() << "Insert failed:" << query.lastError().text();
            return false;
        }

        return true;
    }

    // Nếu chỉ nhập IP (port = 0), port mặc định = 0
    query.prepare("INSERT INTO firewall_rules (ip, port, protocol, action, ip_version) "
                  "VALUES (:ip, :port, :protocol, :action, :ip_version)");
    query.bindValue(":ip", rule.ip());
    query.bindValue(":port", QVariant(static_cast<qlonglong>(rule.port())));
    int protoNor = rule.protocol();   // giờ là số
    query.bindValue(":protocol", protoNor);
    query.bindValue(":action", rule.action());
    query.bindValue(":ip_version", rule.ip_version());

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

bool FirewallViewModel::updateRule(const FirewallRule& rule) {

    // --- 1. Lấy rule cũ ---
    FirewallRule oldRule = getRuleById(rule.id());

    // --- 2. Nếu chuyển từ DENY → ALLOW thì reset conntrack ---
    if (oldRule.action() == "DENY" && rule.action() == "ALLOW") {

        qDebug() << "[Conntrack] Rule changed DENY -> ALLOW. Flushing connection.";

        // IPv4
        QString cmd = QString("conntrack -D -p tcp --dport %1")
                        .arg(rule.port());
        system(cmd.toStdString().c_str());

        // IPv6
        QString cmd6 = QString("conntrack -D -f ipv6 -p tcp --dport %1")
                        .arg(rule.port());
        system(cmd6.toStdString().c_str());
    }

    // --- 3. Cập nhật rule mới vào DB ---
    QSqlQuery query;
    query.prepare("UPDATE firewall_rules "
                  "SET ip = :ip, "
                  "    port = :port, "
                  "    protocol = :protocol, "
                  "    action = :action, "
                  "    ip_version = :ip_version "
                  "WHERE id = :id");

    query.bindValue(":ip", rule.ip());
    query.bindValue(":port", QVariant(static_cast<qlonglong>(rule.port())));
    query.bindValue(":protocol", rule.protocol());
    query.bindValue(":action", rule.action());
    query.bindValue(":ip_version", rule.ip_version());
    query.bindValue(":id", QVariant(static_cast<qlonglong>(rule.id())));

    if (!query.exec()) {
        qDebug() << "Update failed:" << query.lastError().text();
        return false;
    }

    return true;
}

FirewallRule FirewallViewModel::getRuleById(int id) {
    QSqlQuery query;
    query.prepare("SELECT id, ip, port, protocol, action, ip_version "
                  "FROM firewall_rules WHERE id = :id");
    query.bindValue(":id", id);

    if (!query.exec()) {
        qDebug() << "getRuleById failed:" << query.lastError().text();
        return FirewallRule(); // trả về rule rỗng
    }

    if (!query.next()) {
        // Không tìm thấy rule
        return FirewallRule();
    }

    int rid        = query.value("id").toInt();
    QString ip     = query.value("ip").toString();
    int port       = query.value("port").toInt();
    int protocol   = query.value("protocol").toInt();
    QString action = query.value("action").toString();
    int ip_version = query.value("ip_version").toInt();

    return FirewallRule(rid, ip, port, protocol, action, ip_version);
}




QVector<FirewallRule> FirewallViewModel::loadRules() {
    QVector<FirewallRule> rules;
    QSqlQuery query("SELECT id, ip, port, protocol, action, ip_version FROM firewall_rules");
    while (query.next()) {
        int id = query.value(0).toInt();
        QString ip = query.value(1).toString();
        int port = query.value(2).toInt();
        int protocol = query.value(3).toInt();
        QString action = query.value(4).toString();
        int ip_version = query.value(5).toInt();
        rules.append(FirewallRule(id, ip, port, protocol, action, ip_version));
    }
    return rules;
}
//this use to handle the packet from computer to computer
//This is to check the income and out go packet
QString FirewallViewModel::checkPacketIncoming(const FirewallPacket &packet, QSqlDatabase &db, bool ipv6) {
    QSqlQuery query(db);
    if(!query.exec("SELECT ip, port, action, ip_version FROM firewall_rules")) 
        return "ALLOW";

    QString allowAction = "ALLOW";

    while(query.next()) {
        QString ip = query.value(0).toString();
        int port = query.value(1).toInt();
        QString action = query.value(2).toString();
        int ip_version = query.value(3).toInt();

        if((ipv6 && ip_version != 6) || (!ipv6 && ip_version != 4)) continue;

        bool ipWildcardV4 = (ip == "0.0.0.0");
        bool ipWildcardV6 = (ip == "::/0");

        bool ipMatch = (packet.srcIp() == ip) ||
                       (!ipv6 && ipWildcardV4) ||
                       (ipv6 && ipWildcardV6);

        bool portMatch = (port == 0 || packet.srcPort() == port);

        if(ipMatch && portMatch) {
            if(action == "DENY") return "DENY"; 
            else allowAction = "ALLOW";
        }
    }

    return allowAction;
}



QString FirewallViewModel::checkPacketOutgoing(const FirewallPacket &packet, QSqlDatabase &db, bool ipv6) {
    QSqlQuery query(db);
    if(!query.exec("SELECT ip, port, action, ip_version FROM firewall_rules")) 
        return "ALLOW";

    QString allowAction = "ALLOW";

    while(query.next()) {
        QString ip = query.value(0).toString();
        int port = query.value(1).toInt();
        QString action = query.value(2).toString();
        int ip_version = query.value(3).toInt();

        if((ipv6 && ip_version != 6) || (!ipv6 && ip_version != 4)) continue;

        bool ipWildcardV4 = (ip == "0.0.0.0");
        bool ipWildcardV6 = (ip == "::/0");

        bool ipMatch = (packet.desIp() == ip) ||
                       (!ipv6 && ipWildcardV4) ||
                       (ipv6 && ipWildcardV6);

        bool portMatch = (port == 0 || packet.desPort() == port);

        if(ipMatch && portMatch) {
            if(action == "DENY") return "DENY"; 
            else allowAction = "ALLOW";
        }
    }

    return allowAction;
}



//These are the function to callback to the main
int FirewallViewModel::cb_input(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* data) {
        FirewallViewModel* self = static_cast<FirewallViewModel*>(data);
        return self->processIncoming(nfa, qh); 
}
int FirewallViewModel::processIncoming(struct nfq_data* nfa, struct nfq_q_handle* qh) {
    unsigned char* pktData;
    int id = nfq_get_msg_packet_hdr(nfa)->packet_id;
    int len = nfq_get_payload(nfa, &pktData);
    if(len <= 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    QString srcIP;
    int srcPort = 0;
    bool ipv6 = false;
    int protocol = 0;
    QString desIP;
    int desPort = 0;
    // ===== DETECT TCP RST PACKET =====
if (PacketParser::isTCP_RST(pktData)) {
    cout << "[IN] TCP RST detected → ACCEPT\n";
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

    if(PacketParser::isIPv4(pktData)) {
        srcIP = PacketParser::parseIPv4Src(pktData);
        srcPort = PacketParser::parseIPv4SrcPort(pktData);
        desIP = PacketParser::parseIPv4Dst(pktData);
        desPort = PacketParser::parseIPv4DstPort(pktData);
        protocol = pktData[9];

        cout << "[IN][IPv4] " << srcIP.toStdString() << ":" << srcPort
             << " IHL=" << PacketParser::getIPv4HeaderLen(pktData) << "\n";
        cout << "[IN][IPv4] " << srcIP.toStdString() << ":" << srcPort << " → " << desIP.toStdString() << ":" << desPort << "\n";
    }
    else if(PacketParser::isIPv6(pktData)) {
        ipv6 = true;
        srcIP = PacketParser::parseIPv6Src(pktData);
        srcPort = PacketParser::parseIPv6SrcPort(pktData);
        desIP = PacketParser::parseIPv6Dst(pktData);
        desPort = PacketParser::parseIPv6DstPort(pktData);
        protocol = pktData[6];

        cout << "[IN][IPv6] " << srcIP.toStdString() << ":" << srcPort << "\n";
    }
    else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }
    

    FirewallPacket packet(srcIP, desIP, srcPort, desPort, protocol, "");
    QString result = checkPacketIncoming(packet, m_db, ipv6);

    if(result == "DENY") {
        cout << (ipv6 ? "[IN][IPv6]2 " : "[IN]2 ") << "DROP " << srcIP.toStdString() << ":" << srcPort << "\n";
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    } else {
        cout << (ipv6 ? "[IN][IPv6]2 " : "[IN]2 ") << "ACCEPT " << srcIP.toStdString() << ":" << srcPort << "\n";
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }
}




int FirewallViewModel::cb_output(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void* data) {
    FirewallViewModel* self = static_cast<FirewallViewModel*>(data);
    return self->processOutgoing(nfa,qh);
}
int FirewallViewModel::processOutgoing(struct nfq_data* nfa, struct nfq_q_handle* qh) {
    unsigned char* pktData;
    int id = nfq_get_msg_packet_hdr(nfa)->packet_id;
    int len = nfq_get_payload(nfa, &pktData);

    if(len <= 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    QString dstIP;
    int dstPort = 0;
    bool ipv6 = false;
    int protocol = 0;
    QString srcIP;
    int srcPort = 0;

    if(PacketParser::isIPv4(pktData)) {
        dstIP = PacketParser::parseIPv4Dst(pktData);
        dstPort = PacketParser::parseIPv4DstPort(pktData);
        srcIP = PacketParser::parseIPv4Src(pktData);
        srcPort   = PacketParser::parseIPv4SrcPort(pktData);
        protocol = pktData[9];

        cout << "[OUT][IPv4] " << dstIP.toStdString() << ":" << dstPort
             << " IHL=" << PacketParser::getIPv4HeaderLen(pktData) << "\n";
    }
    else if(PacketParser::isIPv6(pktData)) {
        ipv6 = true;
        dstIP = PacketParser::parseIPv6Dst(pktData);
        dstPort = PacketParser::parseIPv6DstPort(pktData);
        srcIP = PacketParser::parseIPv6Src(pktData);
        srcPort   = PacketParser::parseIPv6SrcPort(pktData);
        protocol = pktData[6];

        cout << "[OUT][IPv6] " << dstIP.toStdString() << ":" << dstPort << "\n";
    }
    else {
        cout << "[OUT] UNKNOWN PACKET\n";
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }


    FirewallPacket packet(srcIP, dstIP, srcPort, dstPort, protocol, "");
    QString result = checkPacketOutgoing(packet, m_db, ipv6);

    if(result == "DENY") {

        cout << (ipv6 ? "[OUT][IPv6]2 " : "[OUT]2 ")
             << "REJECT " << dstIP.toStdString() << ":" << dstPort << "\n";

        // ---------- Send TCP RST if the packet is TCP ----------
        if(protocol == IPPROTO_TCP) {
            if(ipv6)
                sendTcpRstIPv6(pktData);
            else
                sendTcpRst(pktData);
        }

        // Drop original packet
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    } else {
        cout << (ipv6 ? "[OUT][IPv6]2 " : "[OUT]2 ") << "ACCEPT " << dstIP.toStdString() << ":" << dstPort << "\n";
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }
}

//This is the functions that is used to reject the packet
// Tính checksum chung
unsigned short FirewallViewModel::checksum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for (int i = 0; i < nwords; i++)
        sum += buf[i];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<unsigned short>(~sum);
}

// Tính TCP checksum với pseudo-header
unsigned short FirewallViewModel::tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, int tcp_len) {
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t length;
    } pseudo;

    pseudo.src = iph->saddr;
    pseudo.dst = iph->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.length = htons(tcp_len);

    int psize = sizeof(pseudo) + tcp_len;
    unsigned char* buf = new unsigned char[psize];

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, tcp_len);

    unsigned short sum = checksum((unsigned short*)buf, psize / 2);
    delete[] buf;
    return sum;
}

void FirewallViewModel::sendTcpRst(const unsigned char* pkt) {
    cout << "\n===== SEND TCP RST IPv4 (FIXED VERSION) =====\n";

    struct iphdr* iph = (struct iphdr*)pkt;
    struct tcphdr* tcph = (struct tcphdr*)(pkt + iph->ihl * 4);

    // Debug src/dst
    char srcIpStr[32], dstIpStr[32];
    inet_ntop(AF_INET, &iph->saddr, srcIpStr, sizeof(srcIpStr));
    inet_ntop(AF_INET, &iph->daddr, dstIpStr, sizeof(dstIpStr));

    cout << "[IPv4] Original Packet:\n";
    cout << "   Src IP: " << srcIpStr
         << " Port: " << ntohs(tcph->source) << "\n";
    cout << "   Dst IP: " << dstIpStr
         << " Port: " << ntohs(tcph->dest)   << "\n";

    // Create raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0){
        perror("[!] socket failed");
        return;
    }

    // Enable custom IP header
    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("[!] setsockopt(IP_HDRINCL) failed");
        close(sock);
        return;
    }

    unsigned char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    struct iphdr* riph = (struct iphdr*)buffer;
    struct tcphdr* rtcph = (struct tcphdr*)(buffer + sizeof(struct iphdr));

    // -------------- BUILD IP HEADER --------------
    riph->version = 4;
    riph->ihl = 5;
    riph->tos = 0;
    riph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    riph->id = htons(0);
    riph->frag_off = 0;
    riph->ttl = 64;
    riph->protocol = IPPROTO_TCP;
    riph->saddr = iph->daddr;  // reverse
    riph->daddr = iph->saddr;

    // -------------- BUILD TCP HEADER --------------
    rtcph->source = tcph->dest; // swap ports
    rtcph->dest   = tcph->source;
    rtcph->doff   = 5;          // no options (20 bytes)
    rtcph->window = htons(65535);
    rtcph->rst    = 1;
    rtcph->ack    = 1;

    // Set SEQ/ACK properly
    if (tcph->syn && !tcph->ack) {
        // Case: responding to SYN
        rtcph->seq     = 0;
        rtcph->ack_seq = htonl(ntohl(tcph->seq) + 1);
    } else {
        // Case: responding to normal TCP packet
        rtcph->seq     = tcph->ack_seq;    // mirror sequence
        rtcph->ack_seq = htonl(ntohl(tcph->seq)); // ack their seq
    }

    // -------------- COMPUTE TCP CHECKSUM --------------
    int tcp_len = rtcph->doff * 4;
    rtcph->check = 0;

    // Pseudo header + padding manually
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    pseudo.src = riph->saddr;
    pseudo.dst = riph->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.len = htons(tcp_len);

    int psize = sizeof(pseudo) + tcp_len;
    bool odd = psize % 2 != 0;

    unsigned char* chksum_buf = new unsigned char[psize + (odd ? 1 : 0)];
    memcpy(chksum_buf, &pseudo, sizeof(pseudo));
    memcpy(chksum_buf + sizeof(pseudo), rtcph, tcp_len);
    if (odd) chksum_buf[psize] = 0;

    rtcph->check = checksum((unsigned short*)chksum_buf,
                            (psize + (odd ? 1 : 0)) / 2);

    delete[] chksum_buf;

    // -------------- COMPUTE IP CHECKSUM --------------
    riph->check = 0;
    riph->check = checksum((unsigned short*)riph, riph->ihl * 2);

    // -------------- SEND PACKET --------------
    struct sockaddr_in target = {};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = riph->daddr;

    int bytes = sendto(sock, buffer,
                       ntohs(riph->tot_len),
                       0,
                       (struct sockaddr*)&target,
                       sizeof(target));

    if(bytes < 0){
        perror("[!] sendto failed");
    } else {
        cout << "[OK] RST sent (" << bytes << " bytes)\n";
    }

    close(sock);
}



unsigned short FirewallViewModel::tcp6_checksum(struct ip6_hdr* iph, struct tcphdr* tcph) {
    struct {
        uint8_t src[16];
        uint8_t dst[16];
        uint32_t tcp_len;
        uint8_t zero[3];
        uint8_t next_hdr;
    } pseudo;

    memcpy(pseudo.src, &iph->ip6_src, 16);
    memcpy(pseudo.dst, &iph->ip6_dst, 16);

    uint32_t tcp_len = sizeof(struct tcphdr);
    pseudo.tcp_len = htonl(tcp_len);
    memset(pseudo.zero, 0, 3);
    pseudo.next_hdr = IPPROTO_TCP;

    int size = sizeof(pseudo) + tcp_len;
    unsigned char* buf = new unsigned char[size];

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, tcp_len);

    unsigned short sum = checksum((unsigned short*)buf, size/2);

    delete[] buf;
    return sum;
}


// Gửi TCP RST cho IPv6
void FirewallViewModel::sendTcpRstIPv6(const unsigned char* pkt) {
    std::cout << "[RSTv6] =====================================================\n";
    std::cout << "[RSTv6] START IPv6 RST GENERATION\n";

    // Parse original IPv6 + TCP
    struct ip6_hdr* iph = (struct ip6_hdr*)pkt;
    struct tcphdr* tcph = (struct tcphdr*)(pkt + sizeof(struct ip6_hdr));

    char srcStr[64], dstStr[64];
    inet_ntop(AF_INET6, &iph->ip6_src, srcStr, sizeof(srcStr));
    inet_ntop(AF_INET6, &iph->ip6_dst, dstStr, sizeof(dstStr));

    std::cout << "[RSTv6] Original packet:\n";
    std::cout << "       SRC IP = " << srcStr << "\n";
    std::cout << "       DST IP = " << dstStr << "\n";
    std::cout << "       SRC PORT = " << ntohs(tcph->source) << "\n";
    std::cout << "       DST PORT = " << ntohs(tcph->dest) << "\n";
    std::cout << "       SEQ = " << ntohl(tcph->seq) << "\n";

    // socket(AF_INET6, RAW)
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0) {
        perror("[RSTv6] socket() FAILED");
        return;
    }
    std::cout << "[RSTv6] socket() OK\n";

    // Enable RAW mode building full headers
    int on = 1;
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) < 0) {
        perror("[RSTv6] setsockopt(IPV6_HDRINCL) FAILED");
        close(sock);
        return;
    }
    std::cout << "[RSTv6] IPV6_HDRINCL enabled\n";

    unsigned char buffer[8192];
    std::memset(buffer, 0, sizeof(buffer));

    struct ip6_hdr* riph = (struct ip6_hdr*)buffer;
    struct tcphdr* rtcph = (struct tcphdr*)(buffer + sizeof(struct ip6_hdr));

    // Reverse IPv6 addresses
    riph->ip6_src = iph->ip6_dst;
    riph->ip6_dst = iph->ip6_src;

    riph->ip6_vfc = 0x60;
    riph->ip6_plen = htons(sizeof(struct tcphdr)); // MUST SET
    riph->ip6_nxt  = IPPROTO_TCP;
    riph->ip6_hlim = 64;

    // Reverse TCP + RST packet
    rtcph->source  = tcph->dest;
    rtcph->dest    = tcph->source;
    rtcph->seq     = 0;
    rtcph->ack_seq = htonl(ntohl(tcph->seq) + 1);
    rtcph->doff    = 5;
    rtcph->rst     = 1;
    rtcph->ack     = 1;
    rtcph->window  = htons(65535);

    rtcph->check = 0;
    rtcph->check = tcp6_checksum(riph, rtcph);

    std::cout << "[RSTv6] Built RST packet:\n";
    char rstSrc[64], rstDst[64];
    inet_ntop(AF_INET6, &riph->ip6_src, rstSrc, sizeof(rstSrc));
    inet_ntop(AF_INET6, &riph->ip6_dst, rstDst, sizeof(rstDst));

    std::cout << "       RST SRC = " << rstSrc << "\n";
    std::cout << "       RST DST = " << rstDst << "\n";
    std::cout << "       PORT " << ntohs(rtcph->source) << " → " << ntohs(rtcph->dest) << "\n";
    std::cout << "       ACK = " << ntohl(rtcph->ack_seq) << "\n";
    std::cout << "       TCP checksum = 0x" << std::hex << rtcph->check << std::dec << "\n";

    struct sockaddr_in6 dst = {};
    dst.sin6_family = AF_INET6;
    dst.sin6_addr = riph->ip6_dst;

    ssize_t sent = sendto(
        sock,
        buffer,
        sizeof(struct ip6_hdr) + sizeof(struct tcphdr),
        0,
        (struct sockaddr*)&dst,
        sizeof(dst)
    );

    if(sent < 0) {
        perror("[RSTv6] sendto() FAILED");
    } else {
        std::cout << "[RSTv6] sendto() OK - bytes sent = " << sent << "\n";
    }

    close(sock);
    std::cout << "[RSTv6] =====================================================\n";
}






