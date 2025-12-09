#!/bin/bash

# Script: run_firewall.sh
# Mục đích: chạy FirewallApp + redirect NFQUEUE + test ping

# ----------------------------
# 1️⃣ Reset iptables
echo "[1/4] Reset iptables..."
sudo iptables -F
sudo iptables -X

# ----------------------------
# 2️⃣ Chạy FirewallApp
echo "[2/4] Running FirewallApp..."
# Chạy app trong background, giữ log in terminal
sudo ./FirewallApp &
FIREWALL_PID=$!

# Đợi 3 giây để FirewallApp attach NFQUEUE
sleep 3

# ----------------------------
# 3️⃣ Thêm iptables rules
echo "[3/4] Adding iptables NFQUEUE rules..."
sudo iptables -A INPUT  -p icmp -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 1

# Kiểm tra
sudo iptables -L -v -n

# ----------------------------
# 4️⃣ Test ping từ Mac (hướng dẫn)
echo "[4/4] Ready for ping test:"
echo "Trên MacBook, chạy: ping 192.168.100.125"

echo "FirewallApp đang chạy với PID=$FIREWALL_PID"
echo "Nhấn Ctrl+C để dừng ping, hoặc Ctrl+C trong terminal này để dừng script."

# ----------------------------
# Giữ script chạy, log của FirewallApp sẽ in ra
wait $FIREWALL_PID
