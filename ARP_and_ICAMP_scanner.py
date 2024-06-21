#!/usr/bin/python3
from scapy.all import sr1
from scapy.layers.inet import IP, ICMP
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether
import ipaddress
import sys

target_network = sys.argv[1]

online_clients = []

ether = Ether(dst='ff:ff:ff:ff:ff:ff')
arp = ARP(pdst=target_network)
probe = ether/arp

result = srp(probe, timeout=3, verbose=0)

answered = result[0]

for sent, received in answered:
    online_clients.append({'ip': received.psrc, "mac": received.hwsrc})

print("[+] Available hosts:")
print("IP"+" "*20 + "MAC")

for client in online_clients:
    print('{}\t\t{}'.format(client["ip"], client['mac']))
#ICMP scanner
print("[+] scanning with icmp")

ip_list = [str(ip) for ip in ipaddress.IPv4Network(target_network, False)]

for ip in ip_list:
    probe = IP(dst=ip)/ICMP()
    result = sr1(probe, timeout=3)
    if result:
        print("[+] {} is online ".format(ip))
