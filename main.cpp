#include <iostream>
#include <QCoreApplication>
#include "FirewallViewModel.h"
#include <QString>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "FirewallViewModel.h"

using namespace std;

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv); 
    FirewallViewModel vm;
    cout << "Start before NFQUEUE" << endl;
    // giả sử id = 0 tạm thời
    // vm.addRule(FirewallRule(QString("192.168.1.1"), 22, QString("TCP"), QString("ALLOW")));
    // vm.addRule(FirewallRule(QString("10.0.0.1"), 22, QString("TCP"), QString("DENY")));

    // vm.deleteRule(2);

    for (const auto& r : vm.loadRules()) {
    std::cout << r.id() << " " 
              << r.ip().toStdString() << " "
              << r.port() << " "
              << r.protocol() << " "
              << r.action().toStdString() << " "
              << r.ip_version() << "\n";
}
    struct nfq_handle* h = nfq_open();
    if (!h) {
        cout << "Error: nfq_open() failed\n";
        return -1;
    }

    // Tắt NFQUEUE cũ từ iptables
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        cout << "Warning: nfq_unbind_pf failed (ignore if first time)\n";
    }

    // Đăng ký lại NFQUEUE
    if (nfq_bind_pf(h, AF_INET) < 0) {
        cout << "Error: nfq_bind_pf() failed\n";
        return -1;
    }

    // ---------- 2. TẠO QUEUE INPUT (queue 0) ----------
    struct nfq_q_handle* q_input =
        nfq_create_queue(h, 0, &FirewallViewModel::cb_input, &vm);
        nfq_set_queue_maxlen(q_input, 8192);

    if (!q_input) {
        cout << "Error: cannot create input queue\n";
        return -1;
    }

    nfq_set_mode(q_input, NFQNL_COPY_PACKET, 0xffff);

    // ---------- 3. TẠO QUEUE OUTPUT (queue 1) ----------
    struct nfq_q_handle* q_output =
        nfq_create_queue(h, 1, &FirewallViewModel::cb_output, &vm);
        nfq_set_queue_maxlen(q_output, 8192);

    if (!q_output) {
        cout << "Error: cannot create output queue\n";
        return -1;
    }

    nfq_set_mode(q_output, NFQNL_COPY_PACKET, 0xffff);

    // ---------- 4. NHẬN PACKET TỪ KERNEL ----------
    int fd = nfq_fd(h);
    int rcvbuf = 8 * 1024 * 1024; // 8MB
if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
    perror("setsockopt(SO_RCVBUF) failed");
}
    char buf[8192] __attribute__((aligned));

    cout << "Firewall is running..." << endl;
    cout << "Database rules loaded: " << vm.loadRules().size() << endl;
    while (true) {
        int len = recv(fd, buf, sizeof(buf), 0);
        if (len >= 0) {
            nfq_handle_packet(h, buf, len);
        }
    }

    nfq_destroy_queue(q_input);
    nfq_destroy_queue(q_output);
    nfq_close(h);

    return 0;
}

